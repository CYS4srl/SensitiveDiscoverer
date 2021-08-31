package burp;

public interface IHttpHeader {
    /**
     * This method is used to retrieve the name of the header.
     *
     * @return The name of the header.
     */
    String getName();

    /**
     * This method is used to retrieve the value of the header.
     *
     * @return The value of the header.
     */
    String getValue();
}
