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
#include <onyx/irq.h>
#include <onyx/arch.h>

static thread_t **idle_threads;

/* TODO: Having a wait queue sounds like a bad idea */
static struct spinlock wait_queue_lock;
static thread_t *wait_queue;
static bool is_initialized = false;

void sched_append_to_queue(int priority, struct processor *p, 
				thread_t *thread);
static void append_to_wait_queue(thread_t *thread);
void sched_block(struct thread *thread);
void __sched_append_to_queue(int priority, struct processor *p, 
				thread_t *thread);
static void __append_to_wait_queue(thread_t *thread);

void sched_lock(struct thread *thread)
{
	/* Order of acquisition in order to avoid a deadlock */
	
	/* 1st - Lock the wait queue */
	/* 2nd - Lock the per-cpu scheduler */
	/* 3rd - Lock the thread */
	
	struct processor *cpu = get_processor_data_for_cpu(thread->cpu);
	spin_lock_irqsave(&wait_queue_lock);

	spin_lock_irqsave(&cpu->scheduler_lock);
	spin_lock_irqsave(&thread->lock);
}

void sched_unlock(struct thread *thread)
{
	struct processor *cpu = get_processor_data_for_cpu(thread->cpu);

	/* Do the reverse of the above */

	spin_unlock_irqrestore(&thread->lock);
	spin_unlock_irqrestore(&cpu->scheduler_lock);
	spin_unlock_irqrestore(&wait_queue_lock);
}

thread_t *__sched_find_next(struct processor *p)
{
	thread_t *current_thread = get_current_thread();

	if(current_thread)
		assert(spin_lock_held(&current_thread->lock) == false);

	/* Note: These locks are unlocked in sched_load_thread, after loading the thread */
	spin_lock_irqsave(&wait_queue_lock);
	spin_lock_irqsave(&p->scheduler_lock);

	if(current_thread)
	{
		spin_lock_irqsave(&current_thread->lock);

		if(current_thread->status == THREAD_BLOCKED)
		{
			__append_to_wait_queue(current_thread);
		}
		else if(current_thread->status == THREAD_RUNNABLE)
		{
			/* Re-append the last thread to the queue */
			__sched_append_to_queue(current_thread->priority,
			p,
			current_thread);
		}
	
		spin_unlock_irqrestore(&current_thread->lock);
	}

	/* Go through the different queues, from the highest to lowest */
	for(int i = NUM_PRIO-1; i >= 0; i--)
	{
		/* If this queue has a thread, we found a runnable thread! */
		if(p->thread_queues[i])
		{
			thread_t *ret = p->thread_queues[i];
			
			/* Advance the queue by one */
			p->thread_queues[i] = ret->next_prio;
			if(p->thread_queues[i])
				ret->prev_prio = NULL;
			ret->next_prio = NULL;

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

void sched_save_thread(struct thread *thread, void *stack)
{
	thread->kernel_stack = stack;
	thread->errno_val = errno;

	arch_save_thread(thread, stack);
}

#define SCHED_QUANTUM		10

void sched_load_thread(struct thread *thread, struct processor *p)
{
	p->current_thread = thread;

	errno = thread->errno_val;

	arch_load_thread(thread, p);

	if(thread->owner)
		arch_load_process(thread->owner, thread, p);

	p->sched_quantum = SCHED_QUANTUM;

	spin_unlock_irqrestore(&p->scheduler_lock);
	spin_unlock_irqrestore(&wait_queue_lock);
}

void *sched_switch_thread(void *last_stack)
{
	struct processor *p = get_processor_data();

	if(is_initialized == 0 || sched_is_preemption_disabled())
	{
		p->sched_quantum = SCHED_QUANTUM;
		return last_stack;
	}

	sched_wake_up_available_threads();
	thread_t *current_thread = p->current_thread;

	if(likely(current_thread))
		sched_save_thread(current_thread, last_stack);

	struct thread *source_thread = current_thread;

	current_thread = sched_find_runnable();

	sched_load_thread(current_thread, p);
	
	if(source_thread && source_thread->status == THREAD_DEAD
	   && source_thread->flags & THREAD_IS_DYING)
	{
		/* Finally, kill the thread for good */
		source_thread->flags &= ~THREAD_IS_DYING; 
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

void __sched_append_to_queue(int priority, struct processor *p, 
thread_t *thread)
{
	MUST_HOLD_LOCK(&p->scheduler_lock);

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
}

void sched_append_to_queue(int priority, struct processor *p, thread_t *thread)
{
	sched_disable_preempt_for_cpu(p);

	spin_lock(&p->scheduler_lock);

	__sched_append_to_queue(priority, p, thread);

	spin_unlock(&p->scheduler_lock);

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
	t->priority = SCHED_PRIO_NORMAL;
	return t;
}

thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_main_progcontext(callback, flags, argc, argv, envp);
	if(!t)
		return NULL;
	t->priority = SCHED_PRIO_NORMAL;
	return t;
}

extern void _sched_yield(void);
int sched_init(void)
{
	idle_threads = malloc(sizeof(void*) * get_nr_cpus());
	assert(idle_threads);
	for(int i = 0; i < get_nr_cpus(); i++)
	{
		idle_threads[i] = task_switching_create_context(sched_idle, 1, NULL);
		assert(idle_threads[i]);
		idle_threads[i]->status = THREAD_IDLE;
		idle_threads[i]->priority = SCHED_PRIO_VERY_LOW;
	}

	is_initialized = true;
	return 0;
}

void sched_yield(void)
{
	__asm__ __volatile__("int $0x81");
}

void sched_sleep(unsigned long ms)
{
	thread_t *current = get_current_thread();
	current->timestamp = get_tick_count();
	current->sleeping_for = ms;
	
	sched_block(current);
}

int __sched_remove_thread_from_execution(thread_t *thread, struct processor *p)
{
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

			return 0;
		}
	}

	return -1;
}

int sched_remove_thread_from_execution(thread_t *thread)
{
	int cpu = thread->cpu;
	struct processor *p = get_processor_data_for_cpu(cpu);
	assert(p != NULL);

	spin_lock_irqsave(&p->scheduler_lock);

	int st = __sched_remove_thread_from_execution(thread, p);

	spin_unlock_irqrestore(&p->scheduler_lock);

	return st;
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

static void __append_to_wait_queue(thread_t *thread)
{
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
}

static void append_to_wait_queue(thread_t *thread)
{
	spin_lock_irqsave(&wait_queue_lock);

	__append_to_wait_queue(thread);
	spin_unlock_irqrestore(&wait_queue_lock);
}

static void __remove_from_wait_queue(thread_t *thread)
{
	assert(thread != NULL);

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
}

static void remove_from_wait_queue(thread_t *thread)
{
	spin_lock_irqsave(&wait_queue_lock);

	__remove_from_wait_queue(thread);
	
	spin_unlock_irqrestore(&wait_queue_lock);
}

void sched_try_to_resched(struct thread *thread)
{
	struct thread *current = get_current_thread();
	if(!current)
		return;

	if(current == thread)
		return;

	if(thread->cpu == current->cpu && thread->priority > current->priority)
	{
		if(is_in_interrupt() || irq_is_disabled())
		{
			current->flags |= THREAD_NEEDS_RESCHED;
			return;
		}

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
	bool try_resched = false;
	assert(thread != NULL);
	
	spin_lock_irqsave(&thread->lock);

	if(thread->status == state)
	{
		spin_unlock_irqrestore(&thread->lock);
		return;
	}

	if(state == THREAD_BLOCKED)
	{
		panic("bug");
		struct processor *p = get_processor_data_for_cpu(thread->cpu);
		assert(p != NULL);
		
		sched_disable_preempt_for_cpu(p);

		thread_t *this_thread = get_current_thread();
		bool is_self = this_thread == thread;

		assert(is_self == false);

		sched_remove_thread_from_execution(thread);
		append_to_wait_queue(thread);

		thread->status = state;

		sched_enable_preempt_for_cpu(p);
	}
	else if(state == THREAD_RUNNABLE)
	{
		struct processor *p = get_processor_data_for_cpu(thread->cpu);
		assert(p != NULL);
		
		/* This may break? */
		sched_disable_preempt_for_cpu(p);

		remove_from_wait_queue(thread);
		thread->status = state;

		if(p->current_thread == thread)
		{
			spin_unlock_irqrestore(&thread->lock);
			sched_enable_preempt_for_cpu(p);
			return;
		}

		sched_append_to_queue(thread->priority, p,
					thread);
		sched_enable_preempt_for_cpu(p);
		try_resched = true;
	}
	else
		thread->status = state;

	spin_unlock_irqrestore(&thread->lock);

	if(try_resched)
		sched_try_to_resched(thread);
}

void __thread_wake_up(struct thread *thread, struct processor *cpu)
{
	MUST_HOLD_LOCK(&wait_queue_lock);
	MUST_HOLD_LOCK(&thread->lock);
	MUST_HOLD_LOCK(&cpu->scheduler_lock);

	/* 1st case: The thread we're "waking up" is running.
	 * In this case, just set the status and return, nothing else needed.
	 * Note: This can happen when in a scheduler primitive, like a mutex.
	*/
	if(cpu->current_thread == thread)
	{
		thread->status = THREAD_RUNNABLE;
		return;
	}
	
	if(thread->status == THREAD_RUNNABLE)
		return;

	thread->status = THREAD_RUNNABLE;
	__remove_from_wait_queue(thread);
	__sched_append_to_queue(thread->priority, cpu, thread);
}

void thread_wake_up(thread_t *thread)
{
	struct processor *p = get_processor_data_for_cpu(thread->cpu);

	sched_lock(thread);

	__thread_wake_up(thread, p);

	sched_unlock(thread);

	/* After waking it up, try and resched it */
	sched_try_to_resched(thread);
}

void sched_block_self(struct thread *thread)
{
	struct processor *cpu = get_processor_data();

	MUST_HOLD_LOCK(&cpu->scheduler_lock);

	thread->status = THREAD_BLOCKED;

	spin_unlock_irqrestore(&thread->lock);
	spin_unlock_irqrestore(&cpu->scheduler_lock);
	spin_unlock_irqrestore(&wait_queue_lock);

	sched_yield();
}

void sched_block_other(struct thread *thread)
{
	struct processor *cpu = get_processor_data_for_cpu(thread->cpu);

	MUST_HOLD_LOCK(&cpu->scheduler_lock);

	thread->status = THREAD_BLOCKED;

	/* TODO: Add support for when the thread is running */
	if(cpu->current_thread == thread)
	{
		panic("ENOSYS");
	}
	else
	{
		__sched_remove_thread_from_execution(thread, cpu);
		__append_to_wait_queue(thread);
	}

	spin_unlock_irqrestore(&thread->lock);
	spin_unlock_irqrestore(&cpu->scheduler_lock);
	spin_unlock_irqrestore(&wait_queue_lock);
}

/* Note: __sched_block returns with everything unlocked */
void __sched_block(struct thread *thread)
{
	struct thread *current = get_current_thread();

	if(current == thread)
	{
		sched_block_self(thread);
	}
	else
	{
		sched_block_other(thread);
	}

}

void sched_block(struct thread *thread)
{
	sched_lock(thread);

	__sched_block(thread);
}

void sched_sleep_until_wake(void)
{
	struct thread *thread = get_current_thread();
	
	sched_block(thread);
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

#define enqueue_thread_generic(primitive_name, primitive_struct) 			\
static void enqueue_thread_##primitive_name(primitive_struct *s, thread_t *thread) 	\
{											\
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
	sched_disable_preempt();

	mutex_unlock(mutex);

	sched_enable_preempt();

	thread_t *current = get_current_thread();

	spin_lock_irqsave(&var->llock);

	sched_lock(current);

	enqueue_thread_condvar(var, current);

	spin_unlock_preempt(&var->llock);

	__sched_block(current);

	mutex_lock(mutex);
}

void condvar_signal(struct cond *var)
{
	spin_lock_irqsave(&var->llock);

	thread_t *thread = var->head;

	if(var->head)
	{
		dequeue_thread_condvar(var, var->head);
		thread_wake_up(thread);
	}

	spin_unlock_irqrestore(&var->llock);
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

void sem_do_slow_path(struct semaphore *sem)
{
	while(sem->counter == 0)
	{
		struct thread *thread = get_current_thread();

		sched_lock(thread);

		enqueue_thread_sem(sem, thread);
				
		spin_unlock_preempt(&sem->lock);

		__sched_block(thread);
	
		spin_lock_irqsave(&sem->lock);
	}
}

void sem_wait(struct semaphore *sem)
{	
	spin_lock_irqsave(&sem->lock);

	while(true)
	{
		if(sem->counter > 0)
		{
			sem->counter--;
			break;
		}
		else
		{
			sem_do_slow_path(sem);
		}
	}

	spin_unlock_irqrestore(&sem->lock);
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

	spin_lock_irqsave(&sem->lock);

	if(sem->head)
		wake_up(sem);

	spin_unlock_irqrestore(&sem->lock);
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

void mutex_lock_slow_path(struct mutex *mutex)
{
	unsigned long irqs = irq_save_and_disable();

	while(!__sync_bool_compare_and_swap(&mutex->counter, 0, 1))
	{
		spin_lock_irqsave(&mutex->llock);

		struct thread *thread = get_current_thread();

		sched_lock(thread);

		enqueue_thread_mutex(mutex, thread);
		
		spin_unlock_preempt(&mutex->llock);

		__sched_block(thread);

		irq_restore(irqs);

		irqs = irq_save_and_disable();
	}

	__sync_synchronize();

	irq_restore(irqs);
}

void mutex_lock(struct mutex *mutex)
{
	if(!__sync_bool_compare_and_swap(&mutex->counter, 0, 1))
		mutex_lock_slow_path(mutex);

	__sync_synchronize();
	mutex->owner = get_current_thread();
}

void mutex_unlock(struct mutex *mutex)
{
	mutex->owner = NULL;
	__sync_bool_compare_and_swap(&mutex->counter, 1, 0);
	__sync_synchronize();

	spin_lock_irqsave(&mutex->llock);

	if(mutex->head)
	{
		sched_disable_preempt();
		struct thread *t = mutex->head;
		dequeue_thread_mutex(mutex, mutex->head);

		thread_wake_up(t);
		sched_enable_preempt();

	}

	spin_unlock_irqrestore(&mutex->llock);
}