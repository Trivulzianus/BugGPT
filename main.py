import os
import random
import importlib.util
import flask
import sqlite3

def list_rooms(base_name, extension):
    """Lists all available room files in the current directory."""
    rooms = []

    for filename in os.listdir(os.getcwd()):
        if filename.startswith(base_name) and filename.endswith(f'.{extension}'):
            rooms.append(filename)

    return rooms

def load_room(room_name):
    """Loads the specified room file."""
    # Build the module name and file path
    module_name = room_name[:-3]  # Remove the .py extension
    file_path = os.path.join(os.getcwd(), room_name)

    # Load the module
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module

if __name__ == '__main__':
    base_name = "Room"
    extension = "py"

    # List available rooms
    rooms = list_rooms(base_name, extension)

    if not rooms:
        print("No room files found.")
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

    # Load the selected room
    room_module = load_room(selected_room)

    # Start the Flask app if it exists
    if hasattr(room_module, 'app'):
        room_module.app.run(debug=False)  # Set debug=False for testing

