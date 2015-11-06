public class InvalidFileException extends RuntimeException {

    private Exception cause;

    public InvalidFileException(Exception cause) {
        this.cause = cause;
    }

    @Override
    public String toString() {
        return "Error reading log. Caused by: \n" + cause.toString();
    }
}
