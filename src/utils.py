import os


def get_files_by_extension(target_path, extension, recursive=False):
    """Return files matching an extension in a file or directory.

    Args:
        target_path: A file or directory to search.
        extension: Filename suffix to match, including its leading dot.
        recursive: Whether to include nested directories.
    """
    if os.path.isfile(target_path) and target_path.endswith(extension):
        return [target_path]

    if not os.path.isdir(target_path):
        return []

    matching_files = []
    if recursive:
        for root, _, filenames in os.walk(target_path):
            matching_files.extend(
                os.path.join(root, filename)
                for filename in filenames
                if filename.endswith(extension)
            )
    else:
        for filename in os.listdir(target_path):
            full_path = os.path.join(target_path, filename)
            if filename.endswith(extension) and os.path.isfile(full_path):
                matching_files.append(full_path)

    return matching_files
