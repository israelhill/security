package project10;

public class InvalidFileException extends RuntimeException {

    private Exception cause;
    private String message;

    public InvalidFileException(Exception cause) {
        this.cause = cause;
        this.message = null;
    }

    public InvalidFileException(String message) {
        this.cause = null;
        this.message = message;
    }

    @Override
    public String toString() {
        if(null == message) {
            return "Error reading log. Caused by: \n" + cause.toString();
        }
        else {
            return "Error reading log: " + message;
        }
    }
}
