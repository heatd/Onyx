/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>

#include <onyx/timer.h>
#include <onyx/data_structures.h>
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/spinlock.h>
#include <onyx/panic.h>
#include <onyx/tss.h>
#include <onyx/process.h>
#include <onyx/idt.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/apic.h>
#include <onyx/worker.h>
#include <onyx/cpu.h>
#include <onyx/semaphore.h>
#include <onyx/condvar.h>

static thread_t **idle_threads;
static struct spinlock wait_queue_lock;
static thread_t *wait_queue;
static bool is_initialized = false;

void sched_append_to_queue(int priority, struct processor *p, 
thread_t *thread);
static void append_to_wait_queue(thread_t *thread);

thread_t *__sched_find_next(struct processor *p)
{
	thread_t *current_thread = get_current_thread();
	if(current_thread)
	{
		if(current_thread->status == THREAD_BLOCKED)
		{
			append_to_wait_queue(current_thread);
			if(current_thread->to_release)
			{
				spin_unlock_preempt(current_thread->to_release);
				current_thread->to_release = NULL;
			}
			spin_unlock_preempt(&current_thread->lock);
		}
		else if(current_thread->status == THREAD_RUNNABLE)
		{
			/* Re-append the last thread to the queue */
			sched_append_to_queue(current_thread->priority,
			p,
			current_thread);
		}
	}
	/* Go through the different queues, from the highest to lowest */
	for(int i = NUM_PRIO-1; i >= 0; i--)
	{
		/* If this queue has a thread, we found a runnable thread! */
		if(p->thread_queues[i])
		{
			thread_t *ret = p->thread_queues[i];
			/* Advance the queue by one (Don't forget to lock!) */
			spin_lock(&p->queue_locks[i]);
			p->thread_queues[i] = ret->next_prio;
			if(p->thread_queues[i])
				ret->prev_prio = NULL;
			ret->next_prio = NULL;
			spin_unlock(&p->queue_locks[i]);
			return ret;
		}
	}
	return NULL;
}

thread_t *sched_find_next(void)
{
	struct processor *p = get_processor_data();
	return __sched_find_next(p);
}

thread_t *sched_find_runnable(void)
{
	thread_t *thread = sched_find_next();
	if(!thread)
	{
		thread_t *current = get_current_thread();
		if(!current)
			return idle_threads[get_cpu_num()];
		if(current->status == THREAD_RUNNABLE)
			return current;
		return idle_threads[get_cpu_num()];
	}
	return thread;
}

bool sched_is_preemption_disabled(void)
{
	struct processor *p = get_processor_data();
	if(!p)
		return false;
	return p->preemption_counter > 0;
}

void *sched_switch_thread(void *last_stack)
{
	if(is_initialized == 0 || sched_is_preemption_disabled())
	{
		return last_stack;
	}

	sched_wake_up_available_threads();
	struct processor *p = get_processor_data();
	thread_t *current_thread = p->current_thread;

	if(unlikely(!current_thread))
	{
		current_thread = sched_find_runnable();
		set_kernel_stack((uintptr_t) current_thread->kernel_stack_top);
		p->kernel_stack = current_thread->kernel_stack_top;
		p->current_thread = current_thread;
		return current_thread->kernel_stack;
	}

	current_thread->kernel_stack = (uintptr_t*) last_stack;
	if(likely(get_current_process()))
	{
		get_current_process()->errno = errno;
	}

	/* Save the FPU state */
	save_fpu(current_thread->fpu_area);

	current_thread = sched_find_runnable();
	p->kernel_stack = current_thread->kernel_stack_top;
	/* Fill the TSS with a kernel stack*/
	set_kernel_stack((uintptr_t) current_thread->kernel_stack_top);
	p->current_thread = current_thread;
	/* Restore the FPU state */
	restore_fpu(current_thread->fpu_area);
	
	if(get_current_process())
	{
		paging_load_cr3(get_current_process()->address_space.cr3);
		errno = get_current_process()->errno;
		wrmsr(FS_BASE_MSR, (uintptr_t) current_thread->fs & 0xFFFFFFFF,
			(uintptr_t)current_thread->fs >> 32);
		wrmsr(KERNEL_GS_BASE,
			(uintptr_t) current_thread->gs & 0xFFFFFFFF,
			(uintptr_t) current_thread->gs >> 32);
	}

	return current_thread->kernel_stack;
}

thread_t *get_current_thread()
{
	struct processor *p = get_processor_data();
	if(unlikely(!p))
		return NULL;
	return (thread_t*) p->current_thread;
}

void sched_idle(void *ptr)
{
	(void) ptr;
	/* This function will not do work at all, just idle using hlt */
	for(;;)
	{
		__asm__ __volatile__("hlt");
	}
}

void sched_append_to_queue(int priority, struct processor *p, 
thread_t *thread)
{
	sched_disable_preempt_for_cpu(p);

	spin_lock(&p->queue_locks[priority]);
	thread_t *queue = p->thread_queues[priority];
	if(!queue)
	{
		p->thread_queues[priority] = thread;
	}
	else
	{
		while(queue->next_prio)
		{
			assert(queue != thread);
			assert(queue != queue->next_prio);
			queue = queue->next_prio;
		}

		assert(queue != thread);

		queue->next_prio = thread;
		thread->prev_prio = queue;
	}
	spin_unlock(&p->queue_locks[priority]);

	sched_enable_preempt_for_cpu(p);
}

int sched_allocate_processor(void)
{
	int nr_cpus = get_nr_cpus();
	int dest_cpu = -1;
	size_t active_threads_min = SIZE_MAX;
	for(int i = 0; i < nr_cpus; i++)
	{
		struct processor *p = get_processor_data_for_cpu(i);
		if(p->active_threads < active_threads_min)
		{
			dest_cpu = i;
			active_threads_min = p->active_threads;
		}
	}
	return dest_cpu;
}

void thread_add(thread_t *thread)
{
	int cpu_num = sched_allocate_processor();
	struct processor *cpu = get_processor_data_for_cpu(cpu_num);

	sched_disable_preempt_for_cpu(cpu);

	thread->cpu = cpu_num;
	cpu->active_threads++;
	/* Append the thread to the queue */
	sched_append_to_queue(thread->priority, cpu, thread);

	sched_enable_preempt_for_cpu(cpu);
}

thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_context(callback, flags, args);
	if(!t)
		return NULL;
	return t;
}

thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_main_progcontext(callback, flags, argc, argv, envp);
	if(!t)
		return NULL;
	return t;
}

extern void _sched_yield();
int sched_init(void)
{
	idle_threads = malloc(sizeof(void*) * get_nr_cpus());
	assert(idle_threads);
	for(int i = 0; i < get_nr_cpus(); i++)
	{
		idle_threads[i] = task_switching_create_context(sched_idle, 1, NULL);
		assert(idle_threads[i]);
		idle_threads[i]->status = THREAD_IDLE;
	}
	is_initialized = true;
	return 0;
}

void sched_yield()
{
	__asm__ __volatile__("int $0x81");
}

void sched_sleep(unsigned long ms)
{
	thread_t *current = get_current_thread();
	current->timestamp = get_tick_count();
	current->sleeping_for = ms;
	thread_set_state(current, THREAD_BLOCKED);
	sched_yield();
}

int sched_remove_thread_from_execution(thread_t *thread)
{
	int cpu = thread->cpu;
	struct processor *p = get_processor_data_for_cpu(cpu);
	assert(p != NULL);

	sched_disable_preempt_for_cpu(p);

	spin_lock(&p->queue_locks[thread->priority]);
	for(thread_t *t = p->thread_queues[thread->priority]; t; t = t->next_prio)
	{
		if(t == thread)
		{
			if(t->prev_prio)
				t->prev_prio->next_prio = t->next_prio;
			else
			{
				p->thread_queues[thread->priority] = t->next_prio;
			}
			if(t->next_prio)
				t->next_prio->prev_prio = t->prev_prio;
			t->prev_prio = NULL;
			t->next_prio = NULL;
			spin_unlock(&p->queue_locks[thread->priority]);

			sched_enable_preempt_for_cpu(p);
			return 0;
		}
	}

	spin_unlock(&p->queue_locks[thread->priority]);

	sched_enable_preempt_for_cpu(p);
	return -1;
}

static void remove_from_wait_queue(thread_t *thread);
void sched_remove_thread(thread_t *thread)
{
	if(sched_remove_thread_from_execution(thread) < 0)
		remove_from_wait_queue(thread);
	thread_set_state(thread, THREAD_DEAD);
}

void set_current_thread(thread_t *t)
{
	get_processor_data()->current_thread = t;
}

pid_t sys_set_tid_address(pid_t *tidptr)
{
	return get_current_thread()->id;
}

int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
	struct timespec ts;
	if(copy_from_user(&ts, req, sizeof(struct timespec)) < 0)
		return -EFAULT;
	time_t ticks = ts.tv_sec * 1000;
	if(ts.tv_nsec)
	{
		if(ts.tv_nsec < 500)
			ticks++;
	}
	sched_sleep(ticks);
	return 0;
}

extern void thread_finish_destruction(void*);

void thread_destroy(thread_t *thread)
{
	/* This function should destroy everything that we can destroy right now.
	 * We can't destroy things like the kernel stack or the FPU area, because we'll eventually 
	 * need to context switch out of here,
	 * or you know, we're actually using the kernel stack right now!
	*/
	
	/* Remove the thread from the queue */
	sched_remove_thread(thread);

	/* We can't actually destroy the user stack because the vm regions are already destroyed */
	
	/* Schedule further thread destruction */
	struct work_request req;
	req.func = thread_finish_destruction;
	req.param = thread;
	worker_schedule(&req, WORKER_PRIO_NORMAL);
}

static void append_to_wait_queue(thread_t *thread)
{
	spin_lock(&wait_queue_lock);

	if(!wait_queue)
	{
		wait_queue = thread;
		thread->prev_wait = NULL;
		thread->next_wait = NULL;
	}
	else
	{
		thread_t *t = wait_queue;
		while(t->next_wait)
		{
			assert(t != thread);
			t = t->next_wait;
		}
			
		t->next_wait = thread;
		thread->prev_wait = t;
		thread->next_wait = NULL;
	}

	spin_unlock(&wait_queue_lock);
}

static void remove_from_wait_queue(thread_t *thread)
{
	assert(thread != NULL);

	spin_lock(&wait_queue_lock);
	if(wait_queue == thread)
	{
		wait_queue = wait_queue->next_wait;
		if(wait_queue) wait_queue->prev_wait = NULL;
		thread->prev_wait = thread->next_wait = NULL;
	}
	else
	{
		for(thread_t *t = wait_queue; t != NULL && t->next_wait != NULL; t = t->next_wait)
		{
			if(t->next_wait == thread)
			{
				t->next_wait = thread->next_wait;
				if(t->next_wait) t->next_wait->prev_wait = t;
				thread->prev_wait = thread->next_wait = NULL;
			}
		}
	}
	spin_unlock(&wait_queue_lock);
}

void sched_try_to_resched(struct thread *thread)
{
	struct thread *current = get_current_thread();

	if(thread->cpu == current->cpu && thread->priority > current->priority)
	{
		/* Just yield, we'll get to execute the thread eventually */
		sched_yield();
	}
	else
	{
		struct processor *cpu = get_processor_data_for_cpu(thread->cpu);

		if(cpu->current_thread->priority < thread->priority)
		{
			/* Send a CPU message asking for a resched */
			cpu_send_message(thread->cpu, CPU_TRY_RESCHED, thread);
		}
	}
}

void thread_set_state(thread_t *thread, int state)
{
	assert(thread != NULL);
	struct processor *targ_cpu = get_processor_data_for_cpu(thread->cpu);

	sched_disable_preempt_for_cpu(targ_cpu);
	
	spin_lock_irqsave(&thread->lock);

	if(thread->status == state)
	{
		spin_unlock_irqrestore(&thread->lock);
		sched_enable_preempt_for_cpu(targ_cpu);
		return;
	}

	if(state == THREAD_BLOCKED)
	{
		thread_t *this_thread = get_current_thread();
		bool is_self = this_thread == thread;

		if(is_self)
		{
			thread->status = state;
			sched_enable_preempt();
			sched_enable_preempt_for_cpu(targ_cpu);
			sched_yield();

			irq_restore(thread->lock.old_flags);
		
			return;
		}
		else
		{
			sched_remove_thread_from_execution(thread);
			append_to_wait_queue(thread);
			thread->status = state;
		}

	}
	else if(state == THREAD_RUNNABLE)
	{
		remove_from_wait_queue(thread);
		thread->status = state;
		struct processor *p = get_processor_data_for_cpu(thread->cpu);
		assert(p != NULL);
		sched_append_to_queue(thread->priority, p,
					thread);
		sched_try_to_resched(thread);
	}
	else
		thread->status = state;

	spin_unlock_irqrestore(&thread->lock);
	sched_enable_preempt_for_cpu(targ_cpu);
}

void thread_wake_up(thread_t *thread)
{
	thread_set_state(thread, THREAD_RUNNABLE);
}

void sched_sleep_until_wake(void)
{
	thread_set_state(get_current_thread(), THREAD_BLOCKED);
	sched_yield();
}

void thread_wake_up_ftx(thread_t *thread)
{
	thread_wake_up(thread);
	thread->woken_up_by_futex = true;
}

void thread_reset_futex_state(thread_t *thread)
{
	thread->woken_up_by_futex = false;
}

void sched_start_thread(thread_t *thread)
{
	assert(thread != NULL);
	thread_add(thread);
}

void sched_wake_up_available_threads(void)
{
	/* Multiple cpus processing this list is a waste of time.
	 * Also, timer interrupts are more than likely to happen at the same time,
	 * as they're all configured for the same rate.
	*/
	if(try_and_spin_lock(&wait_queue_lock) == 1)
		return;
	for(thread_t *thread = wait_queue; thread; thread = thread->next_wait)
	{
		if(thread->timestamp + thread->sleeping_for <= get_tick_count() && 
			thread->sleeping_for != 0)
		{
			/* Remove it from the queue */
			if(thread->prev_wait)
			{
				thread->prev_wait->next_wait = thread->next_wait;
				if(thread->next_wait)
				{
					thread->next_wait->prev_wait = thread->prev_wait;
				}
			}
			else
			{
				wait_queue = thread->next_wait;
				if(wait_queue) wait_queue->prev_wait = NULL;
			}

			thread->timestamp = 0;
			thread->sleeping_for = 0;
			thread->prev_wait = NULL;
			thread->status = THREAD_RUNNABLE;

			struct processor *p = get_processor_data_for_cpu(thread->cpu);
			assert(p != NULL);
			sched_append_to_queue(thread->priority, p,
					      thread);
		}
	}
	spin_unlock(&wait_queue_lock);
}

void thread_suspend_and_release(thread_t *thread, struct spinlock *lock)
{
	spin_lock(&thread->lock);

	assert(__sync_bool_compare_and_swap(&thread->status, THREAD_RUNNABLE, THREAD_BLOCKED));
	
	thread->to_release = lock;

	/* Enable preemption 3 times: 
	 * - Once for the thread->lock
	 * - Another for the lock
	 * - Finallly, the last one, for the sched_disable_preempt that was called
	*/
	sched_enable_preempt();
	sched_enable_preempt();
	sched_enable_preempt();

	sched_yield();
}

#define enqueue_thread_generic(primitive_name, primitive_struct) 			\
static void enqueue_thread_##primitive_name(primitive_struct *s, thread_t *thread) 	\
{ 											\
	spin_lock(&s->llock); 							\
											\
	if(!s->head)									\
	{										\
		s->head = s->tail = thread;						\
		thread->sem_prev = thread->sem_next = NULL;				\
	}										\
	else										\
	{										\
		s->tail->sem_next = thread;						\
		thread->sem_prev = s->tail;						\
		s->tail = thread; 							\
		thread->sem_next = NULL;						\
	}										\
											\
}

#define dequeue_thread_generic(primitive_name, primitive_struct)			\
static void dequeue_thread_##primitive_name(primitive_struct *s, thread_t *thread)	\
{											\
	if(s->head == thread)								\
	{										\
		s->head = thread->sem_next;						\
		if(thread->sem_next)							\
		{									\
			thread->sem_next->sem_prev = NULL;				\
		}									\
											\
	}										\
	else										\
	{										\
		thread->sem_prev->sem_next = thread->sem_next;				\
		if(thread->sem_next)							\
		{									\
			thread->sem_next->sem_prev = thread->sem_prev;			\
		}									\
		else									\
		{									\
			s->tail = thread->sem_prev;					\
		}									\
	}										\
											\
	if(s->tail == thread)								\
	{										\
		s->tail = NULL;								\
	}										\
											\
											\
	thread->sem_next = thread->sem_prev = NULL;					\
											\
}

enqueue_thread_generic(condvar, struct cond);
dequeue_thread_generic(condvar, struct cond);

void condvar_wait(struct cond *var, struct mutex *mutex)
{
	thread_t *current = get_current_thread();

	mutex_unlock(mutex);

	sched_disable_preempt();
	enqueue_thread_condvar(var, current);
	thread_suspend_and_release(current, &var->llock);

	mutex_lock(mutex);
}

void condvar_signal(struct cond *var)
{
	spin_lock(&var->llock);
	
	thread_t *thread = var->head;
	
	if(var->head)
	{
		dequeue_thread_condvar(var, var->head);

		thread_wake_up(thread);
	}

	spin_unlock(&var->llock);
}

void condvar_broadcast(struct cond *var)
{
	while(var->head)	condvar_signal(var);
}

enqueue_thread_generic(sem, struct semaphore);
dequeue_thread_generic(sem, struct semaphore);

void sem_init(struct semaphore *sem, long counter)
{
	sem->counter = (atomic_long) counter;
}

void sem_wait(struct semaphore *sem)
{
	thread_t *current = get_current_thread();
	while(true)
	{
		while(atomic_load_explicit(&sem->counter, memory_order_acquire) < 1)
		{
			sched_disable_preempt();
			enqueue_thread_sem(sem, current);
			thread_suspend_and_release(current, &sem->llock);
		}

		if(atomic_fetch_add_explicit(&sem->counter, -1, memory_order_acq_rel) >= 1)
			break;
		else
			atomic_fetch_add_explicit(&sem->counter, 1, memory_order_release);
	}
}

static void wake_up(struct semaphore *sem)
{
	thread_t *target = sem->head;

	dequeue_thread_sem(sem, target);

	thread_wake_up(target);
}

void sem_signal(struct semaphore *sem)
{
	atomic_fetch_add_explicit(&sem->counter, 1, memory_order_release);

	spin_lock(&sem->llock);
	if(sem->head)
		wake_up(sem);

	spin_unlock(&sem->llock);
}

void sched_enable_preempt_for_cpu(struct processor *cpu)
{
	assert(cpu->preemption_counter > 0);

	atomic_fetch_add_explicit(&cpu->preemption_counter, -1, memory_order_release);
}

void sched_disable_preempt_for_cpu(struct processor *cpu)
{
	atomic_fetch_add_explicit(&cpu->preemption_counter, 1, memory_order_release);
}

void sched_enable_preempt(void)
{
	struct processor *processor = get_processor_data();

	if(!processor)
		return;
	
	sched_enable_preempt_for_cpu(processor);
}

void sched_disable_preempt(void)
{
	struct processor *processor = get_processor_data();
	
	if(!processor)
		return;
	
	sched_disable_preempt_for_cpu(processor);
}

enqueue_thread_generic(mutex, struct mutex);
dequeue_thread_generic(mutex, struct mutex);

void mutex_lock(struct mutex *mutex)
{
	thread_t *thread = get_current_thread();

	while(!__sync_bool_compare_and_swap(&mutex->counter, 0, 1))
	{
		assert(thread != NULL);
		sched_disable_preempt();
		enqueue_thread_mutex(mutex, thread);
		thread_suspend_and_release(thread, &mutex->llock);
	}

	__sync_synchronize();
}

void mutex_unlock(struct mutex *mutex)
{
	__sync_lock_release(&mutex->counter);
	__sync_synchronize();

	spin_lock(&mutex->llock);

	if(mutex->head)
	{
		struct thread *t = mutex->head;
		dequeue_thread_mutex(mutex, mutex->head);

		thread_wake_up(t);
	}

	spin_unlock(&mutex->llock);
}