import matplotlib.pyplot as plt
import numpy as np

# Data
delay_mean = np.array([0, 0.025, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0])
avg_rtt = np.array([2.330, 3.377, 3.729, 4.025, 4.200, 4.277, 4.619, 4.629, 5.412, 6.303, 7.418, 8.643, 9.770, 11.158, 12.522, 13.960, 15.581])

# Create linear scale plot
plt.figure(figsize=(6, 5))
plt.plot(delay_mean, avg_rtt, marker='o', linestyle='-')
plt.xlabel('Random delay mean (ms)')
plt.ylabel('Average RTT (ms)')
plt.grid(True)
plt.tight_layout()

plt.savefig('rtt_linear.png', dpi=300)
plt.show()

# Create logarithmic scale plot
plt.figure(figsize=(6, 5))

# Remove zero since log(0) is undefined
delay_mean_nozero = delay_mean[1:]  
avg_rtt_nozero = avg_rtt[1:]

plt.plot(delay_mean_nozero, avg_rtt_nozero, marker='o', linestyle='-')
plt.xscale('log')

ticks = [0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.0, 3.0, 5.0]
plt.xticks(ticks, [str(t) for t in ticks])

plt.xlabel('Random delay mean (ms) [log scale]')
plt.ylabel('Average RTT (ms)')
plt.grid(True, which='both', linestyle='--')
plt.tight_layout()

plt.savefig('rtt_log.png', dpi=300)
plt.show()
