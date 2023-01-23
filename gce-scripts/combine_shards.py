"""Combines pshtt shards into one final data file."""
# Standard Python Libraries
import json
import sys


def main():
    """Read a file with a list of shard filenames and combine them."""
    if (len(sys.argv)) < 2:
        print("you need a filename!")
        exit(1)
    # Master file is the file with the list of filenames to intake.
    # Fileception.
    master_file = sys.argv[1]
    filenames = []

    # Read in the filenames that are the different shards.
    with open(master_file) as input_file:
        for line in input_file:
            filenames.append(line.rstrip())
    # For each shard, read it in and append to the final list to
    # print out.
    for f in filenames:
        with open(f) as input_file:
            json_data = json.load(input_file)
            for item in json_data:
                print(json.dumps(item))


if __name__ == "__main__":
    main()
