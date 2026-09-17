package testcode.serial;
import java.io.ObjectInputStream;
public class UnsafeDeserialize {
    public Object read(ObjectInputStream in) throws Exception {
        return in.readObject();
    }
}
