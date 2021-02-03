class IllegalParameterException(Exception):
    """
    Exception raised for illegal key parameters during the SRP Protocol.

    Parameters
    ----------
    param
        The illegal parameter
    """

    def __init__(self, param):
        self.param = param
        super().__init__(self.param)

    def __str__(self):
        return f"Parameter {self.param} must not be equal to zero modulo N!"


class InsufficientSecurityException(Exception):
    """
    Exception raised for group parameters N and g with insufficient security.
    """

    def __init__(self):
        super().__init__()

    def __str__(self):
        return "The returned group parameters N and g have insufficient security!"


class NoComparisonAuthHash(Exception):
    """
    Exception raised when a client or server tries to verify an authentication hash
    before calculating an authentication hash to compare to.
    """

    def __init__(self):
        super().__init__()

    def __str__(self):
        return "No authentication hash to compare to!"
