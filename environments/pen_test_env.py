import gymnasium as gym
import nmap
import numpy as np

class PenTestAgent(gym.Env):
    def __init__(self, target_ip):
        super().__init__()
        self.nmap = nmap.PortScanner()
        self.target_ip = target_ip
        self.history = []

        # Expanded action space Adding UDP scan and full port scan
        # 0 SYN Scan (-sS), 1 Service Scan (-sV), 2 OS Detection (-O)
        # 3 Aggressive Scan (-A), 4 Quick Scan (-T4), 5 UDP Scan (-sU)
        # 6 Full Port Scan (1-65535)
        self.action_space = gym.spaces.Discrete(7)

        # Expanded observation space
        max_ports = 10  # Assuming we track up to 10 ports for simplicity
        self.observation_space = gym.spaces.Dict({
            "open_ports": gym.spaces.Box(low=0, high=65535, shape=(max_ports,), dtype=np.int32),
            "services": gym.spaces.MultiDiscrete([100] * max_ports),
            "versions": gym.spaces.MultiDiscrete([100] * max_ports),
            "os_guess": gym.spaces.Discrete(100),
            "port_states": gym.spaces.MultiDiscrete([3] * max_ports),  # 0: closed, 1: open, 2: filtered
            "script_outputs": gym.spaces.MultiDiscrete([100] * max_ports)  # Placeholder for script output encoding
        })

    def step(self, action):
        scan_arguments = {
            0: '-sS',  # SYN Scan
            1: '-sV',  # Service Scan
            2: '-O',   # OS Detection
            3: '-A',   # Aggressive Scan
            4: '-T4',  # Quick Scan
            5: '-sU',  # UDP Scan
            6: '-p 1-65535'  # Full Port Scan
        }.get(action, '-sS')  # Default to SYN Scan for unknown actions
        
        try:
            scan_result = self.nmap.scan(self.target_ip, arguments=scan_arguments)
            self.history.append((action, scan_result))
            
            observation = self._get_observation(scan_result)
            reward = self._get_reward(observation, action)
            done = self._check_done(observation)
            
            return observation, reward, done, {}
        
        except Exception as e:
            print(f"Scan failed: {e}")
            return self.reset(), 0, True, {}

    def reset(self):
        self.history.clear()
        return {
            "open_ports": np.zeros(10, dtype=np.int32),
            "services": np.zeros(10, dtype=np.int32),
            "versions": np.zeros(10, dtype=np.int32),
            "os_guess": 0,
            "port_states": np.zeros(10, dtype=np.int32),
            "script_outputs": np.zeros(10, dtype=np.int32)
        }

    def _get_observation(self, scan_result):
        # Initialize observation with zeros or placeholders
        observation = {
            "open_ports": np.zeros(10, dtype=np.int32),
            "services": np.zeros(10, dtype=np.int32),
            "versions": np.zeros(10, dtype=np.int32),
            "os_guess": 0,
            "port_states": np.zeros(10, dtype=np.int32),
            "script_outputs": np.zeros(10, dtype=np.int32)
        }
        # Example: Extracting more detailed information from scan results
        for i, (port, port_info) in enumerate(scan_result['scan'][self.target_ip].get('tcp', {}).items()):
            if i >= 10:  # Limit to first 10 ports
                break
            observation["open_ports"][i] = port
            observation["port_states"][i] = 1 if port_info['state'] == 'open' else 0
            observation["services"][i] = hash(port_info.get('name', '')) % 100  # Example encoding
            observation["versions"][i] = hash(port_info.get('product', '')) % 100  # Example encoding
            
        # OS guessing
        os_guess_results = scan_result['scan'][self.target_ip].get('osclass', [])
        if os_guess_results:
            observation["os_guess"] = hash(os_guess_results[0].get('osfamily', '')) % 100  # Example encoding
        
        return observation

    def _get_reward(self, observation, action):
        # Initialize reward
        reward = 0
        # Reward for each open port discovered
        open_ports_reward = 10
        reward += np.sum(observation["port_states"] == 1) * open_ports_reward
        # Additional reward for identifying services
        services_reward = 5
        reward += np.sum(observation["services"] > 0) * services_reward
        # Bonus for potential vulnerabilities
        vulnerability_bonus = 20
        reward += np.sum(observation["versions"] == 0) * vulnerability_bonus
        
        return reward

    def _check_done(self, observation):
        # Example criterion for ending an episode
        open_ports_threshold = 5
        open_ports_count = np.sum(observation["port_states"] == 1)
        return open_ports_count >= open_ports_threshold
