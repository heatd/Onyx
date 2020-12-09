/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_CPUMASK_H
#define _ONYX_CPUMASK_H

#ifndef CONFIG_SMP_NR_CPUS
#define CONFIG_SMP_NR_CPUS 64
#endif

constexpr unsigned long cpumask_size_in_longs()
{
	auto long_size_bits = sizeof(unsigned long) * 8;
	auto size = CONFIG_SMP_NR_CPUS / long_size_bits;

	if(CONFIG_SMP_NR_CPUS % long_size_bits)
		size++;

	return size; 
}

class cpumask
{
private:
	static constexpr unsigned long long_size_bits = sizeof(unsigned long) * 8;
	unsigned long mask[cpumask_size_in_longs()];
public:
	explicit constexpr cpumask() : mask{}
	{}

	constexpr void set_cpu(unsigned long cpu)
	{
		auto long_idx = cpu / long_size_bits;
		auto bit_idx = cpu % long_size_bits;

		mask[long_idx] |= (1UL << bit_idx);
	}

	void set_cpu_atomic(unsigned long cpu)
	{
		auto long_idx = cpu / long_size_bits;
		auto bit_idx = cpu % long_size_bits;

		__atomic_or_fetch(&mask[long_idx], (1UL << bit_idx), __ATOMIC_RELAXED);
	}

	constexpr void remove_cpu(unsigned long cpu)
	{
		auto long_idx = cpu / long_size_bits;
		auto bit_idx = cpu % long_size_bits;

		mask[long_idx] &= ~(1UL << bit_idx);
	}

	void remove_cpu_atomic(unsigned long cpu)
	{
		auto long_idx = cpu / long_size_bits;
		auto bit_idx = cpu % long_size_bits;

		__atomic_and_fetch(&mask[long_idx], ~(1UL << bit_idx), __ATOMIC_RELAXED);
	}

	constexpr bool is_cpu_set(unsigned long cpu) const
	{
		auto long_idx = cpu / long_size_bits;
		auto bit_idx = cpu % long_size_bits;

		return mask[long_idx] & (1UL << bit_idx);
	}

	constexpr cpumask& operator|=(unsigned long cpu)
	{
		set_cpu(cpu);

		return *this;
	}

	constexpr cpumask& operator|=(const cpumask& rhs)
	{
		for(unsigned long i = 0; i < cpumask_size_in_longs(); i++)
		{
			mask[i] |= rhs.mask[i];
		}

		return *this;
	}

	constexpr cpumask operator|(const cpumask& rhs) const
	{
		cpumask m{*this};
		return m |= rhs;
	}

	constexpr cpumask operator~()
	{
		cpumask m{*this};
		
		for(unsigned long i = 0; i < cpumask_size_in_longs(); i++)
		{
			m.mask[i] = ~m.mask[i];
		}

		return m;
	}

	constexpr cpumask& operator&=(const cpumask& rhs)
	{
		for(unsigned long i = 0; i < cpumask_size_in_longs(); i++)
		{
			mask[i] &= rhs.mask[i];
		}

		return *this;
	}

	constexpr cpumask operator&(const cpumask& rhs) const
	{
		cpumask m{*this};
		return m &= rhs;
	}

	constexpr cpumask& operator^=(const cpumask& rhs)
	{
		for(unsigned long i = 0; i < cpumask_size_in_longs(); i++)
		{
			mask[i] ^= rhs.mask[i];
		}

		return *this;
	}

	constexpr cpumask operator^(const cpumask& rhs) const
	{
		cpumask m{*this};

		return m ^= rhs;
	}

	template <typename Callable>
	void for_every_cpu(Callable c)
	{
		for(unsigned long i = 0; i < cpumask_size_in_longs(); i++)
		{
			int curr_bit = -1;

			auto word = mask[i];

			/* Nothing to look at here */
			if(word == 0)
				continue;

			while(true)
			{
				if(curr_bit >= 0)
				{
					/* Remove from the input the current bit and the bits before it */
					word &= ~(1UL << curr_bit);
				}

				if(word == 0)
					break;
				/* The word == 0 case has already been dealt with before this */
				curr_bit = __builtin_ffsl(word) - 1;

				auto cpu = long_size_bits * i + curr_bit;

				if(!c(cpu))
					return;
			}
		}
	}

	static constexpr cpumask all()
	{
		return ~cpumask{};
	}

	static constexpr cpumask all_but_one(unsigned long cpu)
	{
		cpumask m;
		m.set_cpu(cpu);
		return ~m;		
	}

	unsigned long *raw_mask()
	{
		return mask;
	}
};

#endif
