
from environments.pen_test_env import PenTestAgent
import numpy as np

def main():
    target_ip = "127.0.0.1"  # Example target IP, replace with actual target IP as needed
    env = PenTestAgent(target_ip)  # Initialize the environment with the target IP
    
    num_episodes = 5  # Number of episodes to run
    
    for episode in range(num_episodes):
        observation = env.reset()  # Reset the environment at the start of each episode
        done = False
        step = 0
        
        while not done:
            action = env.action_space.sample()  # Select a random action from the action space
            observation, reward, done, info = env.step(action)  # Take the action and observe the new state
            
            print(f"Episode: {episode + 1}, Step: {step + 1}, Action: {action}, Reward: {reward}")
            
            if done:
                print(f"Episode {episode + 1} finished after {step + 1} steps.\n")
            step += 1

if __name__ == "__main__":
    main()
