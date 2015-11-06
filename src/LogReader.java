import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogReader {
    private int securityLimit;
    private int blanks;
    private HashMap<User, Integer> map = new HashMap<>();
    private String log;
    private boolean reachedIllegalUsers;
    private static final LogReader logReader = new LogReader();
    private ArrayList<String> blackList = new ArrayList<>();

    private static final String HOST_NAME_PATTERN = "\\(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\)\\:";
    private static final String IP_PATTERN = "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}";
    private static final String FAIL_COUNT_PATTERN = "\\d*\\stimes|\\d*\\stime";

    // Singleton
    private LogReader() {
        // Default security limit is three
        this.securityLimit = 3;
    }

    // get instance of class
    public LogReader getInstance() {
        return logReader;
    }

    public static void main(String[] args) {
        setupStandardOutput();
        logReader.setPrams();

        try {
            logReader.getLogAsString();
            logReader.readFile();
        }
        catch (IOException e) {
            throw new InvalidFileException(e);
        }
        logReader.writeBlackListToFile();
    }

    private static void setupStandardOutput() {
        PrintStream output = null;
        try {
            output = new PrintStream(new FileOutputStream("black_list.txt"));
        }
        catch (FileNotFoundException e) {
            System.out.println("Input file not Found. Please place file in correct directory.");
        }
        System.setOut(output);
    }

    private void setPrams() {
        reachedIllegalUsers = false;
    }

    private void getLogAsString() throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder builder = new StringBuilder();

        String line;
        while((line = br.readLine()) != null) {
            builder.append(line);
            builder.append("\n");
        }
        log = builder.toString();
    }

    private void createBlackList() {
        for(Map.Entry<User, Integer> entry : map.entrySet()) {
            if (entry.getValue() > securityLimit) {
                if(entry.getKey().hasHostName()) {
                    blackList.add(entry.getKey().getHostName());
                }
                else {
                    blackList.add(entry.getKey().getIp());
                }
            }
        }

        for(String s : blackList) {
            System.out.println("Address: " + s);
        }
        System.out.println("\n");
    }

    private void writeBlackListToFile() {
        createBlackList();
        String host;
        final String FIVE_BLANKS = "     ";
        StringBuilder builder = new StringBuilder();
        final int MAX_LINE_LENGTH = 79;

        for(int i = 0; i < blackList.size(); i++) {
            host = blackList.get(i) + ",";
            if((builder.length() + host.length()) < MAX_LINE_LENGTH) {
                builder.append(host);
            }
            else {
                builder.append("\\");
                System.out.println(FIVE_BLANKS + builder.toString());
                builder = new StringBuilder();
                builder.append(host);
            }
        }

        if(builder.length() > 0) {
            // One host left in builder. Remove the comma and print it without a back slash
            String lastLine = builder.toString().substring(0, builder.length() - 1);
            System.out.println(FIVE_BLANKS + lastLine);
        }
    }

    private void readFile() throws IOException {
        try {
            readSecurityLog();
        } catch (InvalidSyntaxException e) {
            throw new InvalidFileException(e);
        }

        System.out.println("\n" + "MAP:");
        for(Map.Entry<User, Integer> entry : map.entrySet()) {
            if(entry.getKey().hasHostName()) {
                System.out.println(entry.getKey().getHostName() + ": " + entry.getValue());
            }
            else {
                System.out.println(entry.getKey().getIp() + ": " + entry.getValue());
            }
        }
        System.out.println("\n\n");
    }

    private void readSecurityLog() throws IOException, InvalidSyntaxException {
        InputStream is = new ByteArrayInputStream(log.getBytes());
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        String line;
        boolean startRead = false;
        blanks = 0;
        while ((line = br.readLine()) != null) {
            checkOrder(line);
            checkFormat();
            if(line.equals("Failed logins from:")) {
                startRead = true;
            }
            else if(startRead && readNextLine(line)) {
                checkFormat();
                String[] portions = line.trim().split(" ");
                isValidLine(portions, portions.length);
            }
        }
        br.close();
    }

    private boolean readNextLine(String line) throws IOException, InvalidSyntaxException {
        if(line.isEmpty()) {
            blanks++;
            checkFormat();
        }

        return (blanks < 2) && !line.isEmpty() && !line.equals("Illegal users from:");
    }

    private void checkOrder(String line) throws InvalidSyntaxException {
        if(line.equals("Failed logins from:")) {
            if(reachedIllegalUsers) {
                throw new InvalidSyntaxException("Illegal user section is before Failed logins");
            }
        }
        else if(line.equals("Illegal users from:")) {
            reachedIllegalUsers = true;
        }
    }

    private void checkFormat() throws InvalidSyntaxException {
        if(!reachedIllegalUsers && blanks > 1) {
            throw new InvalidSyntaxException("Too many blank lines in file.");
        }
    }

    private void isValidLine(String[] portions, int size) {
        String ip;
        String host;
        String count;

        switch(size) {
            case 3: {
                String[] split1 = portions[0].split(":");
                ip = split1[0];
                count = portions[1] + " " + portions[2];
                try {
                    validateTwoArgLine(ip, count);
                }
                catch (InvalidSyntaxException e) {
                    throw new InvalidFileException(e);
                }
                break;
            }
            case 4: {
                ip = portions[0];
                host = portions[1];
                count = portions[2] + " " + portions[3];
                try {
                    validateThreeArgLine(ip, host, count);
                } catch (InvalidSyntaxException e) {
                    throw new InvalidFileException(e);
                }
                break;
            }
            default: {
                String message;
                if(size > 4) {
                    message = "Too many arguments on line.";
                }
                else {
                    message = "Not enough arguments on line";
                }
                throw new InvalidFileException("Problem reading line: " + message);
            }
        }
    }

    private void insertIntoMap(User key, Integer value) {
        if(!map.containsKey(key)) {
            map.put(key, value);
        }
        else {
            int oldValue = map.get(key);
            int newValue = oldValue + value;
            map.put(key, newValue);
        }
    }

    private String getCount(String count) {
        String[] split = count.split(" ");
        return split[0];
    }

    private String getCleanHostName(String host) {
        return host.substring(1, host.length() - 2);
    }

    //BARRICADE METHODS

    public void validateThreeArgLine(String ip, String host, String count) throws InvalidSyntaxException {
        boolean validHost = isValidPattern(HOST_NAME_PATTERN, host);
        boolean validIp = isValidPattern(IP_PATTERN, ip);
        boolean validCount = isValidPattern(FAIL_COUNT_PATTERN, count);

        if(validHost && validIp && validCount) {
            User user = new User(ip, getCleanHostName(host));
            Integer fails = Integer.valueOf(getCount(count));
            insertIntoMap(user, fails);
        }
        else {
            String syntax = ip + " " + host + " " + count;
            throw new InvalidSyntaxException(syntax);
        }
    }

    public void validateTwoArgLine(String ip, String count) throws InvalidSyntaxException {
        boolean validIp = isValidPattern(IP_PATTERN, ip);
        boolean validCount = isValidPattern(FAIL_COUNT_PATTERN, count);

        if(validIp && validCount) {
            User user = new User(ip, null);
            Integer fails = Integer.valueOf(getCount(count));
            insertIntoMap(user, fails);
        }
        else {
            String syntax = ip + " " + count;
            throw new InvalidSyntaxException(syntax);
        }
    }

    public boolean isValidPattern(String regexPattern, String s) {
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher(s);
        return matcher.matches();
    }
}
