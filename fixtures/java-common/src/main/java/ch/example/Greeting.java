package ch.example;

// Fixture: Java with nothing wrong.
public final class Greeting {
    private Greeting() {
    }

    public static String of(String name) {
        return "Hello " + name;
    }
}
