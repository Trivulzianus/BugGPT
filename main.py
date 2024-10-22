import os
import random
import importlib.util
import flask
import sqlite3


def list_room_folders(base_name):
    """Lists all available room folders in the current directory."""
    rooms = []

    for folder_name in os.listdir(os.getcwd()):
        folder_path = os.path.join(os.getcwd(), folder_name)
        if os.path.isdir(folder_path) and folder_name.startswith(base_name):
            rooms.append(folder_name)

    return rooms


def load_room_from_folder(room_folder):
    """Loads the vulnerable app from the specified room folder."""
    vuln_file = os.path.join(room_folder, 'vulnerable_app.py')

    if not os.path.exists(vuln_file):
        print(f"No vulnerable app found in {room_folder}")
        return None

    # Build the module name and load the vulnerable app script
    module_name = f"{room_folder}.vulnerable_app"  # Ensuring unique module names per room
    spec = importlib.util.spec_from_file_location(module_name, vuln_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


if __name__ == '__main__':
    base_name = "Room"

    # List available room folders
    rooms = list_room_folders(base_name)

    if not rooms:
        print("No room folders found.")
        exit()

    print("Available Rooms:")
    for idx, room in enumerate(rooms):
        print(f"{idx + 1}: {room}")

    user_input = input("Enter the room number to run, or type 'random' for a random room: ")

    if user_input.lower() == 'random':
        selected_room = random.choice(rooms)
        print(f"Randomly selected room: {selected_room}")
    else:
        try:
            room_index = int(user_input) - 1
            if 0 <= room_index < len(rooms):
                selected_room = rooms[room_index]
            else:
                print("Invalid room number.")
                exit()
        except ValueError:
            print("Invalid input. Please enter a number or 'random'.")
            exit()

    # Load the selected room's vulnerable app
    room_module = load_room_from_folder(selected_room)

    # Start the Flask app if it exists
    if room_module and hasattr(room_module, 'app'):
        room_module.app.run(debug=False)  # Set debug=False for testing
    else:
        print(f"No Flask app found in {selected_room}")
