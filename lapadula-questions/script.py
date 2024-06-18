import subprocess
import re

def run_command(command):
    """ Run a command in a subprocess and handle its output interactively, including dynamic parsing. """
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1) as proc:
        level_map = {}
        category_set = set()
        levels_marker = '40 Levels'
        categories_marker = '5 Categories'
        can_subject = 'Can a Subject'

        # Process output interactively
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                print(line)  # Ensure all output is printed as it is received

                # Handling different markers and parsing questions
                if levels_marker in line:
                    for i in range(40):
                        level_line = proc.stdout.readline().strip()
                        print(level_line)  # Print the level description
                        if level_line:
                            level_map[level_line] = i
                elif categories_marker in line:
                    for _ in range(5):
                        category_line = proc.stdout.readline().strip()
                        print(category_line)  # Print the category description
                        if category_line:
                            category_set.add(category_line)
                    print(level_map, category_set)
                elif can_subject in line:
                    question_pattern = r"Can a Subject with level (\S+) and categories \{(.*)\} (read|write) an Object with level (\S+) and categories \{(.*)\}"
                    match = re.search(question_pattern, line)
                    if match:
                        subject_level = match.group(1)
                        subject_categories = set(match.group(2).split(', '))
                        print(subject_categories)
                        action = match.group(3)
                        object_level = match.group(4)
                        object_categories = set(match.group(5).split(', '))
                        print(object_categories)
                        # Determine the response based on the parsed information
                        if (action == 'read' and level_map[subject_level] > level_map[object_level]) or (action == 'write' and level_map[subject_level] < level_map[object_level]):
                            response = 'no\n'
                        elif (action == 'read' and not object_categories.issubset(subject_categories)) or (action == 'write' and not subject_categories.issubset(object_categories)):
                            response = 'no\n'
                        elif (action == 'read' and level_map[subject_level] <= level_map[object_level] and not subject_categories) or (action == 'write' and level_map[subject_level] >= level_map[object_level] and not object_categories):
                            response = 'no\n'
                        else:
                            response = 'yes\n'
                        proc.stdin.write(response)
                        proc.stdin.flush()
                    print(object_categories, subject_categories)
        except Exception as e:
            print("Error during output processing:", e)

        # Close stdin and handle process termination
        proc.stdin.close()
        proc.wait()

        # Handle errors
        stderr = proc.stderr.read()
        if stderr:
            print("Errors:", stderr.strip())

        return level_map, category_set

if __name__ == "__main__":
    command = ['/challenge/run']
    run_command(command)

