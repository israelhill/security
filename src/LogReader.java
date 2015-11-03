import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Scanner;

public class LogReader {
    private int securityLimit;

    public LogReader(int limit) {
        this.securityLimit = limit;
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter security limit: ");
        int limit = scanner.nextInt();

        System.out.println("The security limit was set to " + limit);
        LogReader reader = new LogReader(limit);

        try {
            File dir = new File(".");
            File securityLog = new File(dir.getCanonicalPath() + File.separator + "file.txt");
            readFile(securityLog);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void readFile(File file) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(file));

        String line = null;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }

        br.close();
    }
}
