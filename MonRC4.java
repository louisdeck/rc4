// -*- coding: utf-8 -*-

        import java.io.*;
        import java.math.BigInteger;
        import java.nio.file.Files;
        import java.security.MessageDigest;
        import java.security.NoSuchAlgorithmException;
        import java.util.Arrays;
        import java.util.Random;
        import java.util.Scanner;

public class MonRC4 {
    private static int LG_FLUX;
    private static final int n_iterations = 10_000_000;
    private static byte[] clef;

    // Etat interne de RC4
    static byte[] state = new byte[256];
    static int i = 0, j = 0;

    public static byte[] RC4(byte[] fileBytes)
    {
        LG_FLUX = fileBytes.length;

        byte[] octet_chiffrement = new byte[LG_FLUX];
        byte[] result_chiffre = new byte[LG_FLUX];

        initialisation();

        for (int k=0; k<LG_FLUX; k++) {
            octet_chiffrement[k] = production();
            result_chiffre[k] = (byte) (octet_chiffrement[k] ^ fileBytes[k]);
        }
        return result_chiffre;
    }

    public static byte[] HMAC_SHA256(byte[] c, byte[] S)
    {
        int bloc_length = 64;

        if (S.length < bloc_length){
            S = Arrays.copyOf(S,64);
        }
        else if(S.length > bloc_length){
            byte[] tmp = get_resume_SHA256(S);
            S = Arrays.copyOf(tmp,64);
        }

        byte[] ipad = new byte[bloc_length];
        byte[] opad = new byte[bloc_length];

        byte[] S_XOR_ipad = new byte[bloc_length];
        byte[] S_XOR_opad = new byte[bloc_length];

        for (int k = 0; k < bloc_length; k++) {
            ipad[k] = (byte) 0x36;
            opad[k] = (byte) 0x5c;

            S_XOR_ipad[k] = (byte) (S[k] ^ ipad[k]);
            S_XOR_opad[k] = (byte) (S[k] ^ opad[k]);
        }

        byte[] concat = concat(S_XOR_ipad, c);
        byte[] part2 = get_resume_SHA256(concat);

        byte[] ret = get_resume_SHA256(concat(S_XOR_opad,part2));
        return ret;
    }

    public static byte[] PBKDF(byte[] password, byte[] salt, int n)
    {
        byte[] tmp = {(byte) 0x00 , (byte) 0x00, (byte) 0x00, (byte) 0x01};
        byte[][] data = new byte[n][];
        byte[] xor;

        byte[] abc = concat(salt, tmp);
        data[0] = HMAC_SHA256(abc, password);

        if(n==1) return data[0];

        xor = data[0];

        for(int i=1; i<n; i++)
            data[i] = HMAC_SHA256(data[i - 1], password);

        for(int i=1; i<n; i++)
            for(int j=0; j<32; j++)
                xor[j] = (byte) (xor[j] ^ data[i][j]);

        return xor;
    }

    public static void initialisation()
    {
        int lg = clef.length;

        for (i=0; i < 256; i++) state[i] = (byte) i;

        j = 0;
        for (int i=0; i < 256; i++) {
            j = (j + Byte.toUnsignedInt(state[i]) + Byte.toUnsignedInt(clef[i % lg])) % 256;
            echange(i,j);
        }
        i = 0;
        j = 0;
    }

    public static byte production()
    {
        i = (i + 1) % 256;
        j = (j + Byte.toUnsignedInt(state[i])) % 256;
        echange(i,j);
        return state[(Byte.toUnsignedInt(state[i]) + Byte.toUnsignedInt(state[j])) % 256];
    }

    public static byte[] FileToBytes(File file) throws IOException
    {
        byte[] fileContent = Files.readAllBytes(file.toPath());
        return fileContent;
    }

    public static void echange(int k, int l)
    {
        byte temp = state[k];
        state[k] = state[l];
        state[l] = temp;
    }

    public static byte[] concat(byte[] array1, byte[] array2)
    {
        byte[] tmp = Arrays.copyOf(array1,array1.length + array2.length);
        for (int k = array1.length; k < tmp.length; k++) {
            tmp[k] = array2[k - array1.length];
        }
        return tmp;
    }

    public static byte[] get_resume_SHA256(byte[] S)
    {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest.digest(S);
    }

    public static String bytesToHex(byte[] hash)
    {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }


    public static String hexToBytes(byte[] hash)
    {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) throws IOException
    {
        File src = new File(args[1]);
        String dst_name = "";

        if (args[0].equals("-c"))
        {
            if(src.exists()){
                // Générer un sel aléatoire de 8 octects
                Random rd = new Random();
                byte[] s = new byte[8];
                rd.nextBytes(s);

                // Préparer le nom du fichier de sortie("dst.s.rc4")
                dst_name = args[2] + "." + bytesToHex(s) + ".rc4";
                File dst = new File(dst_name);

                if(!dst.exists()){
                    // Demander MDP de l'utilisateur
                    Scanner sc= new Scanner(System.in);
                    System.out.print("Entrez un mot de passe : ");
                    byte[] P = sc.nextLine().getBytes();

                    long start = System.currentTimeMillis();
                    // Faire une clef à partir du sel s et du MDP P
                    clef = PBKDF(P, s, n_iterations);

                    byte[] fileBytes = FileToBytes(src);

                    byte[] result_chiffre = RC4(fileBytes);

                    try (FileOutputStream outputStream = new FileOutputStream(dst))
                    {
                        outputStream.write(result_chiffre);
                    }
                    System.out.println("Le fichier chiffré " + dst_name + " a été généré avec succès.");
                    long end = System.currentTimeMillis();
                    System.out.println("Durée du traitement : " + (end-start)/1000 + " s");
                    return;
                }
                System.out.println("La destination existe déjà, il faut la changer");
            }
            System.out.println("Le fichier source n'existe pas, impossible de chiffrer");
        }

        else if (args[0].equals("-d"))
        {
            if(src.exists()){
                // Demander MDP de l'utilisateur
                Scanner sc= new Scanner(System.in);
                System.out.print("Veuillez entrer votre mot de passe : ");
                byte[] P = sc.nextLine().getBytes();

                // Demander sel utilisé
                sc = new Scanner(System.in);
                System.out.print("Veuillez entre le sel utilisé : ");
                String sel = sc.nextLine();
                byte[] s = new BigInteger(sel, 16).toByteArray();
                File dst = new File(args[2]);

                if(!dst.exists()){

                    long start2 = System.currentTimeMillis();
                    clef = PBKDF(P, s, n_iterations);

                    byte[] fileBytes = FileToBytes(src);

                    byte[] result_chiffre = RC4(fileBytes);

                    try (FileOutputStream outputStream = new FileOutputStream(dst))
                    {
                        outputStream.write(result_chiffre);
                    }
                    System.out.println("Le fichier " + dst_name + " a été déchiffré avec succès.");
                    long end2 = System.currentTimeMillis();
                    System.out.println("Durée du traitement : " + (end2-start2)/1000 + " s");
                    return;
                }
                System.out.println("La destination existe déjà, il faut la changer");
            }
            System.out.println("Le fichier source n'existe pas, impossible de chiffrer");
        }

        else
        {
            System.out.println("Erreur : ");
            System.out.println("MonRC4 -c/-d (path/)file path/file");
        }
    }
}


