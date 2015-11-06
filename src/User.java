public class User {
    private String ip;
    private String hostName;

    public User(String ip, String hostName) {
        this.ip = ip;
        this.hostName = hostName;
    }

    public String getIp() {
        return ip;
    }

    public String getHostName() {
        return hostName;
    }

    public boolean hasHostName() {
        return this.getHostName() != null;
    }

    @Override
    public int hashCode() {
        return this.getIp().hashCode();
    }

    @Override
    public boolean equals(Object object) {
        boolean result = false;
        if (object == null || object.getClass() != getClass()) {
            result = false;
        } else {
            User u = (User) object;
            if (this.getIp().equals(u.getIp())) {
                result = true;
            }
        }
        return result;
    }
}
