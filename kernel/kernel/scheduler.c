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
#include <onyx/task_switching.h>
#include <onyx/vm.h>
#include <onyx/spinlock.h>
#include <onyx/panic.h>
#include <onyx/tss.h>
#include <onyx/process.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/worker.h>
#include <onyx/cpu.h>
#include <onyx/semaphore.h>
#include <onyx/condvar.h>
#include <onyx/irq.h>
#include <onyx/arch.h>
#include <onyx/percpu.h>
#include <onyx/rwlock.h>
#include <onyx/clock.h>
#include <onyx/dpc.h>

#include <libdict/rb_tree.h>


static bool is_initialized = false;

void sched_append_to_queue(int priority, unsigned int cpu, 
				thread_t *thread);
void sched_block(struct thread *thread);
void __sched_append_to_queue(int priority, unsigned int cpu, 
				thread_t *thread);

int sched_rbtree_cmp(const void *t1, const void *t2);
static struct rb_tree glbl_thread_list = {.cmp_func = sched_rbtree_cmp};
static struct spinlock glbl_thread_list_lock;

PER_CPU_VAR(struct spinlock scheduler_lock);
PER_CPU_VAR(struct thread *thread_queues_head[NUM_PRIO]);
PER_CPU_VAR(struct thread *thread_queues_tail[NUM_PRIO]);
PER_CPU_VAR(struct thread *current_thread);

void thread_append_to_global_list(struct thread *t)
{
	spin_lock(&glbl_thread_list_lock);

	dict_insert_result res = rb_tree_insert(&glbl_thread_list, (void *) (unsigned long) t->id);
	assert(res.inserted == true);
	*res.datum_ptr = t;

	spin_unlock(&glbl_thread_list_lock);
}

void thread_remove_from_list(struct thread *t)
{
	spin_lock(&glbl_thread_list_lock);

	dict_remove_result res = rb_tree_remove(&glbl_thread_list, (void *) (unsigned long) t->id);
	assert(res.removed != false);

	spin_unlock(&glbl_thread_list_lock);
}

char *thread_strings[] =
{
	"THREAD_RUNNABLE",
	"THREAD_INTERRUPTIBLE",
	"THREAD_SLEEPING",
	"THREAD_IDLE",
	"THREAD_DEAD",
	"THREAD_UNINTERRUPTIBLE",
	"THREAD_STOPPED"
};

bool _dump_thread(const void *key, void *_thread, void *of)
{
	struct thread *thread = _thread;

	printk("Thread id %d\n", thread->id);

	if(thread->owner)
		printk("User space thread - owner %s\n", thread->owner->cmd_line);

	printk("Thread status: %s\n", thread_strings[thread->status]);
	if(thread->status == THREAD_INTERRUPTIBLE || thread->status == THREAD_UNINTERRUPTIBLE)
	{
		struct registers *regs = (struct registers *) thread->kernel_stack;
		printk("Dumping context. IP = %016lx, RBP = %016lx\n", regs->rip, regs->rbp);
		stack_trace_ex((uint64_t *) regs->rbp);
	}

	return true;
}

void vterm_panic(void);

void sched_dump_threads(void)
{
	vterm_panic();
	//spin_lock(&glbl_thread_list_lock);

	rb_tree_traverse(&glbl_thread_list, _dump_thread, NULL);
	
	//spin_unlock(&glbl_thread_list_lock);
}

struct thread *thread_get_from_tid(int tid)
{
	spin_lock(&glbl_thread_list_lock);

	void **pp = rb_tree_search(&glbl_thread_list, (const void *) (unsigned long) tid);
	
	struct thread *t = NULL;
	if(pp)
	{
		t = *pp;
		thread_get(t);
	}

	spin_unlock(&glbl_thread_list_lock);

	return t;
}

FUNC_NO_DISCARD
unsigned long sched_lock(struct thread *thread)
{
	/* Order of acquisition in order to avoid a deadlock */
	
	/* 1st - Lock the per-cpu scheduler */
	/* 2nd - Lock the thread */
	
	struct spinlock *l = get_per_cpu_ptr_any(scheduler_lock, thread->cpu);

	unsigned long cpu_flags = spin_lock_irqsave(l);
	unsigned long _ =spin_lock_irqsave(&thread->lock);
	(void) _;

	return cpu_flags;
}

void sched_unlock(struct thread *thread, unsigned long cpu_flags)
{
	struct spinlock *l = get_per_cpu_ptr_any(scheduler_lock, thread->cpu);

	/* Do the reverse of the above */

	spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
	spin_unlock_irqrestore(l, cpu_flags);
}

thread_t *__sched_find_next(unsigned int cpu)
{
	thread_t *current_thread = get_current_thread();

	if(current_thread)
		assert(spin_lock_held(&current_thread->lock) == false);

	/* Note: These locks are unlocked in sched_load_thread, after loading the thread */
	struct spinlock *sched_lock = get_per_cpu_ptr_any(scheduler_lock, cpu);
	unsigned long _ =spin_lock_irqsave(sched_lock);
	(void) _;

	struct thread **thread_queues = (struct thread **) get_per_cpu_ptr_any(thread_queues_head, cpu);

	if(current_thread)
	{
		unsigned long cpu_flags = spin_lock_irqsave(&current_thread->lock);

		if(current_thread->status == THREAD_RUNNABLE)
		{
			/* Re-append the last thread to the queue */
			__sched_append_to_queue(current_thread->priority,
			cpu,
			current_thread);
		}
	
		spin_unlock_irqrestore(&current_thread->lock, cpu_flags);
	}

	/* Go through the different queues, from the highest to lowest */
	for(int i = NUM_PRIO-1; i >= 0; i--)
	{
		/* If this queue has a thread, we found a runnable thread! */
		if(thread_queues[i])
		{
			thread_t *ret = thread_queues[i];
			
			/* Advance the queue by one */
			thread_queues[i] = ret->next_prio;
			if(thread_queues[i])
				ret->prev_prio = NULL;
			ret->next_prio = NULL;

			return ret;
		}
	}

	return NULL;
}

thread_t *sched_find_next(void)
{
	return __sched_find_next(get_cpu_nr());
}

thread_t *sched_find_runnable(void)
{
	thread_t *thread = sched_find_next();
	if(!thread)
	{
		panic("sched_find_runnable: no runnable thread");
	}
	return thread;
}

PER_CPU_VAR(unsigned long preemption_counter) = 0;

bool sched_is_preemption_disabled(void)
{
	return get_per_cpu(preemption_counter) > 0;
}

void sched_save_thread(struct thread *thread, void *stack)
{
	thread->kernel_stack = stack;
	thread->errno_val = errno;

	arch_save_thread(thread, stack);
}

#define SCHED_QUANTUM		10

PER_CPU_VAR(uint32_t sched_quantum) = 0;
PER_CPU_VAR(struct clockevent sched_pulse);

void sched_decrease_quantum(struct clockevent *ev)
{
	add_per_cpu(sched_quantum, -1);

	if(get_per_cpu(sched_quantum) == 0)
	{
		struct thread *curr = get_current_thread();
		curr->flags |= THREAD_NEEDS_RESCHED;
	}

	ev->deadline = clocksource_get_time() + NS_PER_MS;
}

void sched_load_thread(struct thread *thread, unsigned int cpu, unsigned long og_cpuflags)
{
	write_per_cpu_any(current_thread, thread, cpu);

	errno = thread->errno_val;

	arch_load_thread(thread, cpu);

	if(thread->owner)
		arch_load_process(thread->owner, thread, cpu);

	write_per_cpu_any(sched_quantum, SCHED_QUANTUM, cpu);

	cputime_restart_accounting(thread);

	spin_unlock_irqrestore(get_per_cpu_ptr_any(scheduler_lock, cpu), og_cpuflags);
}

void sched_load_finish(struct thread *prev_thread, struct thread *next_thread)
{	
	arch_context_switch(prev_thread, next_thread);
}

unsigned long st_invoked = 0;

void *sched_switch_thread(void *last_stack)
{
	if(!is_initialized || sched_is_preemption_disabled())
	{
		add_per_cpu(sched_quantum, 1);
		return last_stack;
	}

	thread_t *curr_thread = get_per_cpu(current_thread);

	if(likely(curr_thread))
	{
		bool thread_blocked = curr_thread->status == THREAD_INTERRUPTIBLE ||
	                          curr_thread->status == THREAD_UNINTERRUPTIBLE;

		if(thread_blocked && curr_thread->flags & THREAD_ACTIVE)
		{
			write_per_cpu(sched_quantum, 1);
			curr_thread->flags &= ~THREAD_ACTIVE;
			return last_stack;
		}

		curr_thread->flags &= ~THREAD_ACTIVE;

		sched_save_thread(curr_thread, last_stack);

		do_cputime_accounting();
	}

	struct thread *source_thread = curr_thread;
	unsigned long original_cpuflags = irq_save_and_disable();

	curr_thread = sched_find_runnable();
	st_invoked++;

	sched_load_thread(curr_thread, get_cpu_nr(), original_cpuflags);
	
	if(source_thread && source_thread->status == THREAD_DEAD
	   && source_thread->flags & THREAD_IS_DYING)
	{
		/* Finally, kill the thread for good */
		source_thread->flags &= ~THREAD_IS_DYING; 
	}

	sched_load_finish(source_thread, curr_thread);
	__builtin_unreachable();

	panic("sched_load_finish returned");
}

strong_alias(sched_switch_thread, asm_schedule);

void *sched_preempt_thread(void *current_stack)
{
	struct thread *t = get_current_thread();

	if(t) t->flags |= THREAD_ACTIVE;

	COMPILER_BARRIER();

	void *ret = sched_switch_thread(current_stack);

	if(t) t->flags &= ~THREAD_ACTIVE;

	COMPILER_BARRIER();

	return ret;
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

void __sched_append_to_queue(int priority, unsigned int cpu, 
				struct thread *thread)
{
	MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, cpu));

	assert(thread->status == THREAD_RUNNABLE);

	struct thread **thread_queues = (struct thread **) get_per_cpu_ptr_any(thread_queues_head, cpu);
	thread_t *queue = thread_queues[priority];
	if(!queue)
	{
		thread_queues[priority] = thread;
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

void sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread)
{
	spin_lock(get_per_cpu_ptr_any(scheduler_lock, cpu));

	__sched_append_to_queue(priority, cpu, thread);

	spin_unlock(get_per_cpu_ptr_any(scheduler_lock, cpu));
}

PER_CPU_VAR(unsigned long active_threads) = 0;

unsigned int sched_allocate_processor(void)
{
	unsigned int nr_cpus = get_nr_cpus();
	unsigned int dest_cpu = -1;
	size_t active_threads_min = SIZE_MAX;
	
	for(unsigned int i = 0; i < nr_cpus; i++)
	{
		unsigned long active_threads_for_cpu = get_per_cpu_any(active_threads, i);
		if(active_threads_for_cpu < active_threads_min)
		{
			dest_cpu = i;
			active_threads_min = active_threads_for_cpu;
		}
	}
	return dest_cpu;
}

void thread_add(thread_t *thread, unsigned int cpu_num)
{
	if(cpu_num == SCHED_NO_CPU_PREFERENCE)
		cpu_num = sched_allocate_processor();

	thread->cpu = cpu_num;
	add_per_cpu_any(active_threads, 1, cpu_num);
	/* Append the thread to the queue */
	sched_append_to_queue(thread->priority, cpu_num, thread);
}

void sched_init_cpu(unsigned int cpu)
{
	struct thread *t = sched_create_thread(sched_idle, THREAD_KERNEL, NULL);

	assert(t != NULL);

	t->priority = SCHED_PRIO_VERY_LOW;
	t->cpu = cpu;

	write_per_cpu_any(current_thread, t, cpu);
	write_per_cpu_any(sched_quantum, SCHED_QUANTUM, cpu);
	write_per_cpu_any(preemption_counter, 0, cpu);
}

void sched_enable_pulse(void)
{
	struct clockevent *ev = get_per_cpu_ptr(sched_pulse);
	ev->callback = sched_decrease_quantum;
	ev->deadline = clocksource_get_time() + NS_PER_MS;
	ev->flags = CLOCKEVENT_FLAG_ATOMIC | CLOCKEVENT_FLAG_PULSE;
	ev->priv = NULL;

	timer_queue_clockevent(ev);
}

int sched_rbtree_cmp(const void *t1, const void *t2)
{
	int tid0 = (int) (unsigned long) t1;
	int tid1 = (int) (unsigned long) t2;
	return tid1 - tid0;
}

int sched_init(void)
{
	struct thread *t = sched_create_thread(sched_idle, THREAD_KERNEL, NULL);

	assert(t != NULL);

	t->priority = SCHED_PRIO_NORMAL;
	//sched_start_thread_for_cpu(t, get_cpu_nr());

	write_per_cpu(sched_quantum, SCHED_QUANTUM);
	set_current_thread(t);
	sched_enable_pulse();

	is_initialized = true;
	return 0;
}

void platform_yield(void);

void sched_yield(void)
{
	if(sched_is_preemption_disabled())
		panic("Thread tried to sleep with preemption disabled");
	
	platform_yield();
}

void sched_sleep_unblock(struct clockevent *v)
{
	struct thread *t = v->priv;
	thread_wake_up(t);
}

hrtime_t sched_sleep(unsigned long ns)
{
	thread_t *current = get_current_thread();

	struct clockevent ev;
	ev.callback = sched_sleep_unblock;
	ev.priv = current;

	/* This clockevent can run atomically because it's a simple thread_wake_up,
	 * which is save to call from atomic/interrupt context.
	 */
	ev.flags = CLOCKEVENT_FLAG_ATOMIC;
	ev.deadline = clocksource_get_time() + ns;
	timer_queue_clockevent(&ev);

	/* This is a bit of a hack but we need this in cases where we have timeout but we're not supposed to be
	 * woken by signals. In this case, wait_for_event_* already set the current state.
	 */
	if(get_current_thread()->status == THREAD_RUNNABLE)
		set_current_state(THREAD_INTERRUPTIBLE);

	sched_yield();

	/* Lets remove the event in the case where we got woken up by a signal or by another thread */
	timer_remove_event(&ev);

	hrtime_t t1 = clocksource_get_time();
	hrtime_t rem = t1 - ev.deadline;
	
	/* It's okay if we wake up slightly after we wanted to, just return success */
	if(t1 > ev.deadline)
		rem = 0;

	return rem;
}

int __sched_remove_thread_from_execution(thread_t *thread, unsigned int cpu)
{
	struct thread **thread_queues = (struct thread **) get_per_cpu_ptr_any(thread_queues_head, cpu);

	for(thread_t *t = thread_queues[thread->priority]; t; t = t->next_prio)
	{
		if(t == thread)
		{
			if(t->prev_prio)
				t->prev_prio->next_prio = t->next_prio;
			else
			{
				thread_queues[thread->priority] = t->next_prio;
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
	unsigned int cpu = thread->cpu;

	struct spinlock *s = get_per_cpu_ptr_any(scheduler_lock, cpu);
	unsigned long cpu_flags = spin_lock_irqsave(s);

	int st = __sched_remove_thread_from_execution(thread, cpu);

	spin_unlock_irqrestore(s, cpu_flags);

	return st;
}

void sched_remove_thread(thread_t *thread)
{
	sched_remove_thread_from_execution(thread);
	thread_set_state(thread, THREAD_DEAD);
}

void set_current_thread(thread_t *t)
{
	write_per_cpu(current_thread, t);
}

pid_t sys_set_tid_address(pid_t *tidptr)
{
	struct thread *t = get_current_thread();
	t->ctid = tidptr;
	return t->id;
}

int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
	struct timespec ts;
	if(copy_from_user(&ts, req, sizeof(struct timespec)) < 0)
		return -EFAULT;

	if(!timespec_valid(&ts, false))
		return -EINVAL;

	hrtime_t ns = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;

	hrtime_t ns_rem = sched_sleep(ns);

	if(rem)
	{
		ts.tv_sec = ns_rem / NS_PER_SEC;
		ts.tv_nsec = ns_rem % NS_PER_SEC;

		if(copy_to_user(rem, &ts, sizeof(struct timespec)) < 0)
			return -EFAULT;
	}

	if(rem && signal_is_pending())
		return -EINTR;

	return 0;
}

extern void thread_finish_destruction(void*);

void thread_destroy(struct thread *thread)
{
	/* This function should destroy everything that we can destroy right now.
	 * We can't destroy things like the kernel stack or the FPU area, because we'll eventually 
	 * need to context switch out of here,
	 * or you know, we're actually using the kernel stack right now!
	*/

	if(thread->owner)
	{
		__atomic_sub_fetch(&thread->owner->nr_threads, 1, __ATOMIC_RELAXED);

		spin_lock(&thread->owner->thread_list_lock);
		list_remove(&thread->thread_list_head);
		spin_unlock(&thread->owner->thread_list_lock);
	}

	/* Remove the thread from the queue */
	sched_remove_thread(thread);

	/* We can't actually destroy the user stack because the vm regions are already destroyed */
	
	/* Schedule further thread destruction */
	struct dpc_work w;
	w.context = thread;
	w.funcptr = thread_finish_destruction;
	w.next = NULL;
	dpc_schedule_work(&w, DPC_PRIORITY_MEDIUM);
}

void sched_die(void)
{
	sched_disable_preempt();

	struct thread *current = get_current_thread();

	/* We need to switch to the fallback page directory while we can, because
	 * we don't know if the current pgd will be destroyed by some other thread.
	 */
	vm_switch_to_fallback_pgd();

	current->status = THREAD_DEAD;
	current->flags |= THREAD_IS_DYING;

	sched_enable_preempt();
	sched_yield();
}

struct thread *get_thread_for_cpu(unsigned int cpu)
{
	return get_per_cpu_any(current_thread, cpu);
}

bool sched_may_resched(void)
{
	return !(is_in_interrupt() || irq_is_disabled() || sched_is_preemption_disabled());
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
		if(!sched_may_resched())
		{
			current->flags |= THREAD_NEEDS_RESCHED;
			return;
		}

		/* Just yield, we'll get to execute the thread eventually */
		sched_yield();
	}
	else
	{
		struct thread *other_thread = get_thread_for_cpu(thread->cpu);
		int other_prio = other_thread->priority;
		if(other_prio < thread->priority)
		{
			/* Send a CPU message asking for a resched */
			cpu_send_resched(thread->cpu);
		}
	}
}

void thread_set_state(thread_t *thread, int state)
{
	bool try_resched = false;
	assert(thread != NULL);
	
	unsigned long cpu_flags = spin_lock_irqsave(&thread->lock);

	if(thread->status == state)
	{
		spin_unlock_irqrestore(&thread->lock, cpu_flags);
		return;
	}

	thread->status = state;

	spin_unlock_irqrestore(&thread->lock, cpu_flags);

	if(try_resched)
		sched_try_to_resched(thread);
}

void __thread_wake_up(struct thread *thread, unsigned int cpu)
{
	MUST_HOLD_LOCK(&thread->lock);
	MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, cpu));

	/* 1st case: The thread we're "waking up" is running.
	 * In this case, just set the status and return, nothing else needed.
	 * Note: This can happen when in a scheduler primitive, like a mutex.
	*/
	if(get_thread_for_cpu(cpu) == thread)
	{
		thread->status = THREAD_RUNNABLE;
		return;
	}
	
	if(thread->status == THREAD_RUNNABLE)
		return;

	thread->status = THREAD_RUNNABLE;
	__sched_append_to_queue(thread->priority, cpu, thread);
}

void thread_wake_up(thread_t *thread)
{
	unsigned long f = sched_lock(thread);

	__thread_wake_up(thread, thread->cpu);

	sched_unlock(thread, f);

	/* After waking it up, try and resched it */
	sched_try_to_resched(thread);
}

void sched_block_self(struct thread *thread, unsigned long fl)
{
	MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, thread->cpu));

	thread->status = THREAD_UNINTERRUPTIBLE;

	spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
	spin_unlock_irqrestore(get_per_cpu_ptr_any(scheduler_lock, thread->cpu), fl);

	sched_yield();
}

void sched_block_other(struct thread *thread)
{
	panic("not implemented");
}

/* Note: __sched_block returns with everything unlocked */
void __sched_block(struct thread *thread, unsigned long fl)
{
	struct thread *current = get_current_thread();

	if(current == thread)
	{
		sched_block_self(thread, fl);
	}
	else
	{
		sched_block_other(thread);
	}

}

void sched_block(struct thread *thread)
{
	unsigned long f = sched_lock(thread);

	__sched_block(thread, f);
}

void sched_sleep_until_wake(void)
{
	struct thread *thread = get_current_thread();
	
	sched_block(thread);
}

void sched_start_thread_for_cpu(struct thread *t, unsigned int cpu)
{
	assert(t != NULL);
	thread_add(t, cpu);
}

void sched_start_thread(thread_t *thread)
{
	sched_start_thread_for_cpu(thread, SCHED_NO_CPU_PREFERENCE);
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
		if(thread->sem_prev) thread->sem_prev->sem_next = thread->sem_next;	\
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
		s->tail = thread->sem_prev;						\
	}										\
											\
											\
	thread->sem_next = thread->sem_prev = NULL;					\
											\
}

enqueue_thread_generic(condvar, struct cond);
dequeue_thread_generic(condvar, struct cond);

void condvar_wait_unlocked(struct cond *var)
{
	thread_t *current = get_current_thread();

	bool b = irq_is_disabled();

	unsigned long _ =spin_lock_irqsave(&var->llock);
	(void) _;

	unsigned long f = sched_lock(current);

	enqueue_thread_condvar(var, current);

	spin_unlock_preempt(&var->llock);

	__sched_block(current, f);

	if(!b) irq_enable();
}

void condvar_wait(struct cond *var, struct mutex *mutex)
{
	sched_disable_preempt();

	mutex_unlock(mutex);

	sched_enable_preempt();

	condvar_wait_unlocked(var);

	mutex_lock(mutex);
}

void condvar_signal(struct cond *var)
{
	unsigned long cpu_flags = spin_lock_irqsave(&var->llock);

	thread_t *thread = var->head;

	if(var->head)
	{
		dequeue_thread_condvar(var, var->head);
		thread_wake_up(thread);
	}

	spin_unlock_irqrestore(&var->llock, cpu_flags);
}

void condvar_broadcast(struct cond *var)
{
	unsigned long cpu_flags = spin_lock_irqsave(&var->llock);

	while(var->head)
	{
		thread_t *t = var->head;
		if(t->sem_next)
			t->sem_next->sem_prev = NULL;

		var->head = t->sem_next;
		t->sem_next = NULL;

		thread_wake_up(t);
	}

	spin_unlock_irqrestore(&var->llock, cpu_flags);
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

		unsigned long f = sched_lock(thread);

		enqueue_thread_sem(sem, thread);
				
		spin_unlock(&sem->lock);

		__sched_block(thread, f);
	
		spin_lock(&sem->lock);
	}
}

void sem_wait(struct semaphore *sem)
{	
	spin_lock(&sem->lock);

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

	spin_unlock(&sem->lock);
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

	unsigned long cpu_flags = spin_lock_irqsave(&sem->lock);

	if(sem->head)
		wake_up(sem);

	spin_unlock_irqrestore(&sem->lock, cpu_flags);
}

/* TODO: Optimise these code paths */

void sched_enable_preempt_for_cpu(unsigned int cpu)
{
	unsigned long *preempt_counter = get_per_cpu_ptr_any(preemption_counter, cpu); 

	//assert(*preempt_counter > 0);

	atomic_fetch_add_explicit(preempt_counter, -1, memory_order_relaxed);
}

void sched_disable_preempt_for_cpu(unsigned int cpu)
{
	unsigned long *preempt_counter = get_per_cpu_ptr_any(preemption_counter, cpu); 
	atomic_fetch_add_explicit(preempt_counter, 1, memory_order_relaxed);
}

void sched_try_to_resched_if_needed(void)
{
	struct thread *current = get_current_thread();

	if(current && sched_needs_resched(current) && sched_may_resched())
	{
		sched_yield();
		current->flags &= ~THREAD_NEEDS_RESCHED;
	}
}

void sched_enable_preempt_no_softirq(void)
{
	add_per_cpu(preemption_counter, -1);

	sched_try_to_resched_if_needed();
}

void sched_enable_preempt(void)
{
	//assert(*preempt_counter > 0);

	add_per_cpu(preemption_counter, -1);
	
	if(get_per_cpu(preemption_counter) == 0 && !irq_is_disabled())
		softirq_try_handle();

	sched_try_to_resched_if_needed();	
}

void sched_disable_preempt(void)
{
	add_per_cpu(preemption_counter, 1);
}

#define prepare_sleep_generic(typenm, type) 			\
void prepare_sleep_##typenm(type *p, int state)			\
{							\
	struct thread *t = get_current_thread(); 	\
	sched_disable_preempt();			\
							\
	set_current_state(state);			\
	unsigned long __cpu_flags = spin_lock_irqsave(&p->llock);			\
	enqueue_thread_##typenm(p, t);			\
	spin_unlock_irqrestore(&p->llock, __cpu_flags);		\
}

void __sched_kill_other(struct thread *thread, unsigned int cpu)
{
	MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, thread->cpu));

	cpu_send_message(cpu, CPU_KILL_THREAD, NULL, false);
}

pid_t sys_gettid(void)
{
	struct thread *current = get_current_thread();
	/* TODO: Should we emulate actual linux behavior? */
	return current->id;
}

bool rw_lock_tryread(struct rwlock *lock)
{
	unsigned long l;
	do
	{
		l = lock->lock;
		if(l == RDWR_LOCK_WRITE - 1)
			return errno = EAGAIN, false;
		if(l == RDWR_LOCK_WRITE)
			return errno = EBUSY, false;
	} while(__sync_bool_compare_and_swap(&lock->lock, l, l+1) != true);
	
	__sync_synchronize();

	return true;
}

bool rw_lock_trywrite(struct rwlock *lock)
{
	bool st = __sync_bool_compare_and_swap(&lock->lock, 0, RDWR_LOCK_WRITE);
	__sync_synchronize();
	
	return st;
}

static void commit_sleep()
{
	sched_yield();
}

enqueue_thread_generic(rwlock, struct rwlock);
dequeue_thread_generic(rwlock, struct rwlock);
prepare_sleep_generic(rwlock, struct rwlock);

int __rw_lock_write(struct rwlock *lock, int state)
{
	/* Try once before doing the whole preempt disable loop and all */
	if(rw_lock_trywrite(lock))
		return 0;

	int ret = 0;
	struct thread *current = get_current_thread();

	bool signals_allowed = state == THREAD_INTERRUPTIBLE;

	prepare_sleep_rwlock(lock, state);

	while(!rw_lock_trywrite(lock))
	{
		if(signals_allowed && signal_is_pending())
		{
			ret = -EINTR;
			break;
		}

		sched_enable_preempt();

		commit_sleep();

		prepare_sleep_rwlock(lock, state);
	}

	unsigned long cpu_flags = spin_lock_irqsave(&lock->llock);

	dequeue_thread_rwlock(lock, current);

	spin_unlock_irqrestore(&lock->llock, cpu_flags);

	set_current_state(THREAD_RUNNABLE);

	sched_enable_preempt();

	__sync_synchronize();

	return ret;
}

int __rw_lock_read(struct rwlock *lock, int state)
{
	/* Try once before doing the whole preempt disable loop and all */
	if(rw_lock_tryread(lock))
		return 0;

	int ret = 0;
	struct thread *current = get_current_thread();

	bool signals_allowed = state == THREAD_INTERRUPTIBLE;

	prepare_sleep_rwlock(lock, state);

	while(!rw_lock_tryread(lock))
	{
		if(signals_allowed && signal_is_pending())
		{
			ret = -EINTR;
			break;
		}

		sched_enable_preempt();

		commit_sleep();

		prepare_sleep_rwlock(lock, state);
	}

	unsigned long cpu_flags = spin_lock_irqsave(&lock->llock);

	dequeue_thread_rwlock(lock, current);

	spin_unlock_irqrestore(&lock->llock, cpu_flags);

	set_current_state(THREAD_RUNNABLE);

	sched_enable_preempt();

	__sync_synchronize();

	return ret;
}

void rw_lock_write(struct rwlock *lock)
{
	__rw_lock_write(lock, THREAD_UNINTERRUPTIBLE);
}

int rw_lock_write_interruptible(struct rwlock *lock)
{
	return __rw_lock_write(lock, THREAD_INTERRUPTIBLE);
}

void rw_lock_read(struct rwlock *lock)
{
	__rw_lock_read(lock, THREAD_UNINTERRUPTIBLE);
}

int rw_lock_read_interruptible(struct rwlock *lock)
{
	return __rw_lock_read(lock, THREAD_INTERRUPTIBLE);
}

void rw_lock_wake_up_threads(struct rwlock *lock)
{
	spin_lock(&lock->llock);

	while(lock->head)
	{
		struct thread *to_wake = lock->head;
		dequeue_thread_rwlock(lock, lock->head);

		thread_wake_up(to_wake);
	}

	spin_unlock(&lock->llock);
}

void rw_lock_wake_up_thread(struct rwlock *lock)
{
	spin_lock(&lock->llock);

	if(lock->head)
	{
		struct thread *to_wake = lock->head;
		dequeue_thread_rwlock(lock, lock->head);

		thread_wake_up(to_wake);
	}

	spin_unlock(&lock->llock);
}

void rw_unlock_read(struct rwlock *lock)
{
	/* Implementation note: If we're unlocking a read lock, only wake up a
	 * single thread, since the write lock is exclusive, like a mutex.
	*/
	if(__sync_sub_and_fetch(&lock->lock, 1) == 0)
		rw_lock_wake_up_thread(lock);
}

void rw_unlock_write(struct rwlock *lock)
{
	lock->lock = 0;
	__sync_synchronize();
	/* Implementation note: If we're unlocking a write lock, wake up every single thread
	 * because we can have both readers and writers waiting to get woken up.
	*/
	rw_lock_wake_up_threads(lock);
}

void sched_transition_to_idle(void)
{
	struct thread *curr = get_current_thread();
	curr->priority = SCHED_PRIO_VERY_LOW;
	curr->entry(NULL);
}

int sched_transition_to_user_thread(struct thread *thread)
{
	int st = 0;
	if((st = arch_transform_into_user_thread(thread)) < 0)
		return st;

	thread->flags &= ~THREAD_KERNEL;
	return st;
}
