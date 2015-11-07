package project10;

public class InvalidSyntaxException extends Exception {
    private String syntax;

    public InvalidSyntaxException(String syntax) {
        this.syntax = syntax;
    }

    @Override
    public String toString() {
        return "Invalid log syntax:  " + this.syntax;
    }
}
