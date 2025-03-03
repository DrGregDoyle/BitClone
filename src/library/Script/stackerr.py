class StackError(Exception):
    """Base exception for stack operations."""
    pass


class EmptyStackError(StackError):
    """Raised when attempting to access or remove elements from an empty stack."""
    pass


class StackIndexError(StackError):
    """Raised when attempting to access an invalid stack index."""
    pass


class InsufficientElementsError(StackError):
    """Raised when an operation requires more elements than available."""

    def __init__(self, message="Not enough elements on stack", required=None, available=None):
        self.required = required
        self.available = available
        if required is not None and available is not None:
            message = f"{message}. Required: {required}, Available: {available}"
        super().__init__(message)
