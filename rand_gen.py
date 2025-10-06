#rand char gen for testing input  

import random
import string

def generate_random_characters(length):
    # Define the pool of characters to choose from
    characters = string.ascii_letters + string.digits + string.punctuation

    random_string = ''.join(random.choice(characters) for _ in range(length))
    
    return random_string

def main():
    print("Random Character Generator")
    print("--------------------------")
    
    try:
        length = int(input("Enter the number of characters to generate: "))
        
        if length <= 0:
            print("Please enter a positive number.")
            return
        
        random_chars = generate_random_characters(length)
        
        print("\nGenerated Random Characters in File.")
        #print(random_chars)
        
        print(f"\nLength: {len(random_chars)} characters generated.")
        
        with open('random_chars_output.txt', 'w') as file:
            file.write("Generated Random Characters:\n")
            file.write(random_chars + "\n")
            file.write(f"\nLength: {len(random_chars)} characters\n")
        
        print("\nResults have been saved to 'random_chars_output.txt'")
        
    except ValueError:
        print("Invalid input. Please enter a valid number.")

if __name__ == "__main__":
    main()