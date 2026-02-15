module FlootyPermissions

export validate_no_traversal, validate_safe_extension, is_within_workspace
export DANGEROUS_EXTENSIONS, is_dangerous_extension
export validate_new_file, validate_directory
export normalize_path, is_safe_filename, splitext, tempdir

# ============================================================================
# Configuration
# ============================================================================

"""
    DANGEROUS_EXTENSIONS

File extensions that could be executed or pose security risks.
These are blocked from creation operations.
"""
const DANGEROUS_EXTENSIONS = Set([
    ".exe", ".dll", ".bat", ".cmd", ".sh",     # Executables
    ".bin", ".app", ".msi", ".dmg",            # Installers/binaries
    ".so", ".dylib", ".o", ".a",               # Libraries
    ".jar", ".class", ".pyc", ".pyo",          # Compiled code
    ".ps1", ".vbs", ".js", ".wsf",             # Scripts
    ".com", ".scr", ".gadget"                  # Legacy Windows
])

# ============================================================================
# Path Traversal Prevention
# ============================================================================

"""
    validate_no_traversal(path::String) -> Bool

Check that path does not contain traversal patterns that escape the workspace.

Returns true if path is safe, false if traversal detected.
"""
function validate_no_traversal(path::String)::Bool
    # Normalize path separators
    normalized = replace(path, "\\" => "/")

    # Check for obvious traversal patterns
    # Pattern 1: Starts with .. (relative parent)
    if startswith(normalized, "..")
        return false
    end

    # Pattern 2: Contains /../ anywhere
    if occursin("/../", normalized)
        return false
    end

    # Pattern 3: Ends with /..
    if endswith(normalized, "/..")
        return false
    end

    # Pattern 4: Contains .. without proper separators (e.g., ".../")
    # This catches creative attempts like "....//" which normalizes to "../"
    parts = split(normalized, "/")
    for part in parts
        # Check for patterns that could normalize to traversal
        if part == ".." || startswith(part, "..")
            return false
        end
    end

    # Pattern 5: Null bytes (injection attempt)
    if occursin("\0", path)
        return false
    end

    return true
end

# ============================================================================
# Extension Safety
# ============================================================================

"""
    is_dangerous_extension(path::String) -> Bool

Check if file extension is in the dangerous list.
"""
function is_dangerous_extension(path::String)::Bool
    # Extract extension (lowercase for comparison)
    ext = lowercase(get_extension(path))
    return ext in DANGEROUS_EXTENSIONS
end

"""
    validate_safe_extension(path::String) -> Bool

Check that path does not have a dangerous extension.

Returns true if safe, false if dangerous extension detected.
"""
function validate_safe_extension(path::String)::Bool
    return !is_dangerous_extension(path)
end

"""
    get_extension(path::String) -> String

Get the file extension from a path (including the dot).
"""
function get_extension(path::String)::String
    # Find last dot after last directory separator
    normalized = replace(path, "\\" => "/")

    # Get just the filename
    filename = basename(normalized)

    # Find last dot
    dot_pos = findlast('.', filename)

    if dot_pos === nothing || dot_pos == 1  # No dot or hidden file (.gitignore)
        return ""
    end

    return filename[dot_pos:end]
end

"""
    basename(path::String) -> String

Get the filename portion of a path.
"""
function basename(path::String)::String
    normalized = replace(path, "\\" => "/")
    parts = split(normalized, "/")
    return parts[end]
end

# ============================================================================
# Workspace Validation
# ============================================================================

"""
    is_within_workspace(path::String, workspace::String=pwd()) -> Bool

Check that the absolute path of `path` is within or equal to `workspace`.

Returns true if within workspace, false otherwise.
"""
function is_within_workspace(path::String, workspace::String=pwd())::Bool
    try
        # Get absolute paths and normalize separators
        abs_path = replace(abspath(path), "\\" => "/")
        abs_workspace = replace(abspath(workspace), "\\" => "/")

        # Normalize: ensure both end with / for proper prefix check
        if !endswith(abs_workspace, "/")
            abs_workspace *= "/"
        end

        # Check if path is workspace itself or within workspace
        normalized_path = abs_path * (endswith(abs_path, "/") ? "" : "/")

        # Path is valid if:
        # 1. It's exactly the workspace, OR
        # 2. It starts with workspace/
        return abs_path == replace(abspath(workspace), "\\" => "/") || startswith(normalized_path, abs_workspace)
    catch e
        return false
    end
end

# ============================================================================
# Combined Validation
# ============================================================================

"""
    validate_new_file(path::String, workspace::String=pwd()) -> Tuple{Bool, String}

Validate a new file path for all safety checks.

Returns (is_valid, error_message).
"""
function validate_new_file(path::String, workspace::String=pwd())::Tuple{Bool,String}
    # Check traversal
    if !validate_no_traversal(path)
        return (false, "Path traversal detected: path cannot contain '..' patterns")
    end

    # Check extension
    if !validate_safe_extension(path)
        ext = get_extension(path)
        return (false, "Dangerous file extension blocked: $ext")
    end

    # Check workspace
    if !is_within_workspace(path, workspace)
        abs_path = abspath(path)
        abs_workspace = abspath(workspace)
        return (false, "Path outside workspace: $abs_path not within $abs_workspace")
    end

    return (true, "")
end

"""
    validate_directory(path::String, workspace::String=pwd()) -> Tuple{Bool, String}

Validate a directory path for creation.

Returns (is_valid, error_message).
"""
function validate_directory(path::String, workspace::String=pwd())::Tuple{Bool,String}
    # Check traversal
    if !validate_no_traversal(path)
        return (false, "Path traversal detected: path cannot contain '..' patterns")
    end

    # Check workspace
    if !is_within_workspace(path, workspace)
        abs_path = abspath(path)
        abs_workspace = abspath(workspace)
        return (false, "Path outside workspace: $abs_path not within $abs_workspace")
    end

    return (true, "")
end

# ============================================================================
# Utility Functions
# ============================================================================

"""
    normalize_path(path::String) -> String

Normalize path for consistent comparison.
"""
function normalize_path(path::String)::String
    return abspath(replace(path, "\\" => "/"))
end

"""
    is_safe_filename(filename::String) -> Bool

Check if a filename is safe (no special chars, not reserved names).
"""
function is_safe_filename(filename::String)::Bool
    # Windows reserved names
    reserved = Set(["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
        "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
        "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"])

    # Get base name without extension
    base = splitext(filename)[1]
    if uppercase(base) in reserved
        return false
    end

    # Check for special characters
    unsafe_chars = ['<', '>', ':', '"', '|', '?', '*', '\0']
    for c in unsafe_chars
        if occursin(c, filename)
            return false
        end
    end

    return true
end

"""
    splitext(filename::String) -> Tuple{String, String}

Split filename into (name, extension).
"""
function splitext(filename::String)::Tuple{String,String}
    dot_pos = findlast('.', filename)
    if dot_pos === nothing || dot_pos == 1
        return (filename, "")
    end
    return (filename[1:dot_pos-1], filename[dot_pos:end])
end

"""
    tempdir() -> String

Get the system's temporary directory path.

Returns the path with trailing separator removed for consistency.
"""
function tempdir()::String
    td = Base.tempdir()
    # Remove trailing separator if present
    if endswith(td, Base.Filesystem.path_separator)
        return td[1:end-1]
    end
    return td
end

end # module FlootyPermissions
