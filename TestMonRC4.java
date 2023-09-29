import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(OrderAnnotation.class)
public class TestMonRC4
{

    @Test
    @Order(1)
    @DisplayName("[Exo 1] Vérifie que le résultat de la fonction HMAC_SHA256 est égal au tableau d'octets final de l'énoncé")
    public void testVectors()
    {
        byte[] c = {(byte) 0x48, (byte) 0x69, (byte) 0x20, (byte) 0x74, (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x65};
        byte[] S = new byte[20];

        byte[] expected = {(byte) 0xB9, (byte) 0x83, (byte) 0x35, (byte) 0x9E, (byte) 0xB3, (byte) 0x8E, (byte) 0x43, (byte) 0xCF, (byte) 0x34, (byte) 0xC6, (byte) 0x9B, (byte) 0x63,
                (byte) 0x3F, (byte) 0xD5, (byte) 0xD6, (byte) 0x09, (byte) 0xB2, (byte) 0xFC, (byte) 0x3A, (byte) 0x7E, (byte) 0x93, (byte) 0xD9, (byte) 0xA0, (byte) 0x54, (byte) 0xD0,
                (byte) 0x5D, (byte) 0x1F, (byte) 0xED, (byte) 0x76, (byte) 0xDB, (byte) 0x28, (byte) 0x94};

        for(int i=0; i<20; i++)
            S[i] = (byte) 0x0b;

        byte[] res = MonRC4.HMAC_SHA256(c, S);
        Assertions.assertArrayEquals(expected, res);

        //for(int i=0; i<32; i++)
        //    System.out.printf("0x%02X ", res[i]);
    }

    @Test
    @Order(2)
    @DisplayName("[Exo 2] Vérifie la clé U1 avec les données de l'énoncé")
    public void testU1()
    {
        byte[] password = "passwd".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] expected = {(byte) 0x55, (byte) 0xAC, (byte) 0x04, (byte) 0x6E, (byte) 0x56, (byte) 0xE3, (byte) 0x08, (byte) 0x9F, (byte) 0xEC, (byte) 0x16, (byte) 0x91, (byte) 0xC2,
                (byte) 0x25, (byte) 0x44, (byte) 0xB6, (byte) 0x05, (byte) 0xF9, (byte) 0x41, (byte) 0x85, (byte) 0x21, (byte) 0x6D, (byte) 0xDE, (byte) 0x04, (byte) 0x65, (byte) 0xE6,
                (byte) 0x8B, (byte) 0x9D, (byte) 0x57, (byte) 0xC2, (byte) 0x0D, (byte) 0xAC, (byte) 0xBC};

        byte[] res = MonRC4.PBKDF(password, salt, 1);
        Assertions.assertArrayEquals(expected, res);
    }

    @Test
    @Order(3)
    @DisplayName("[Exo 2] Vérifie la clé Uk avec les données de l'énoncé")
    public void testUk()
    {
        byte[] password = "Password".getBytes();
        byte[] salt = "NaCl".getBytes();
        byte[] expected = {(byte) 0x4d, (byte) 0xdc, (byte) 0xd8, (byte) 0xf6, (byte) 0x0b, (byte) 0x98, (byte) 0xbe, (byte) 0x21, (byte) 0x83, (byte) 0x0c, (byte) 0xee, (byte) 0x5e,
                (byte) 0xf2, (byte) 0x27, (byte) 0x01, (byte) 0xf9, (byte) 0x64, (byte) 0x1a, (byte) 0x44, (byte) 0x18, (byte) 0xd0, (byte) 0x4c, (byte) 0x04, (byte) 0x14, (byte) 0xae,
                (byte) 0xff, (byte) 0x08, (byte) 0x87, (byte) 0x6b, (byte) 0x34, (byte) 0xab, (byte) 0x56};

        byte[] res = MonRC4.PBKDF(password, salt, 80000);
        Assertions.assertArrayEquals(expected, res);
    }
}