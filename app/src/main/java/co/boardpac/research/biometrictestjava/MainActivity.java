package co.boardpac.research.biometrictestjava;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    private static final String KEY_NAME_NOT_INVALIDATED = "key_not_invalidated";
    private static final String DEFAULT_KEY_NAME = "default_key_name";
    private static final String SECRET_MESSAGE = "Very secret message";
    private static final String TAG = "MainActivity";

    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private SharedPreferences sharedPreferences;
    private BiometricPrompt biometricPrompt;
    private Executor executor;
    Button validatedButton, notValidatedButton;
    TextView textViewConfirmation, textViewEncryptedMessage;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        validatedButton = findViewById(R.id.button_validated);
        notValidatedButton = findViewById(R.id.button_notvalidated);
        textViewConfirmation = findViewById(R.id.textViewConfirmation);
        textViewEncryptedMessage = findViewById(R.id.textViewEncryptedMessage);

        setupKeyStoreAndKeyGenerator();
        Cipher defaultCipher = getDefaultCipher();
        Cipher notValidatedCipher = getNotValidatedCipher();
        biometricPrompt = createBiometricPrompt();
        setUpPurchaseButtons(notValidatedCipher,defaultCipher);
    }

    private void setUpPurchaseButtons(final Cipher cipherNotInvalidated, final Cipher defaultCipher) {


        BiometricManager biometricManager = BiometricManager.from(this);
        switch (biometricManager.canAuthenticate()) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                validatedButton.setEnabled(true);
                notValidatedButton.setEnabled(true);
                Log.d("MY_APP_TAG", "App can authenticate using biometrics.");
                createKey(DEFAULT_KEY_NAME, true);
                createKey(KEY_NAME_NOT_INVALIDATED, false);
                validatedButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        textViewConfirmation.setVisibility(View.GONE);
                        textViewEncryptedMessage.setVisibility(View.GONE);
                        BiometricPrompt.PromptInfo promptInfo = createPromptInfo();
                        if(initCipher(defaultCipher,DEFAULT_KEY_NAME)){
                            biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(defaultCipher));
                        }
                    }
                });
                notValidatedButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        textViewConfirmation.setVisibility(View.GONE);
                        textViewEncryptedMessage.setVisibility(View.GONE);
                        BiometricPrompt.PromptInfo promptInfo = createPromptInfo();
                        if(initCipher(cipherNotInvalidated,KEY_NAME_NOT_INVALIDATED)){
                            biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipherNotInvalidated));
                        }
                    }
                });
                break;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.e("MY_APP_TAG", "No biometric features available on this device.");
                validatedButton.setEnabled(false);
                notValidatedButton.setEnabled(false);
                break;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                validatedButton.setEnabled(false);
                notValidatedButton.setEnabled(false);
                Log.e("MY_APP_TAG", "Biometric features are currently unavailable.");
                break;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                validatedButton.setEnabled(false);
                notValidatedButton.setEnabled(false);
                Log.e("MY_APP_TAG", "The user hasn't associated " +
                        "any biometric credentials with their account.");
                break;
        }
    }

    private void setupKeyStoreAndKeyGenerator() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (Exception e){
            throw  e;
        }

    }

    private Cipher getDefaultCipher() {
        Cipher defaultCipher = null;
        String cipherString = KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7;
        try {
            defaultCipher = Cipher.getInstance(cipherString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        } catch (Exception e) {
            throw e;
        }
        return defaultCipher;
    }

    private Cipher getNotValidatedCipher() {
        Cipher cipherNotInvalidated = null;
        String cipherString = "AES/CBC/PKCS7Padding";
        try {
            cipherNotInvalidated = Cipher.getInstance(cipherString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        } catch (Exception e) {
            throw e;
        }
        return cipherNotInvalidated;
    }

    private BiometricPrompt createBiometricPrompt() {
        executor = ContextCompat.getMainExecutor(this);
        biometricPrompt = new BiometricPrompt(MainActivity.this,
                executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT)
                        .show();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(getApplicationContext(),
                        "Authentication succeeded!", Toast.LENGTH_SHORT).show();
                if(result.getCryptoObject()!=null && result.getCryptoObject().getCipher()!=null) {
                    byte[] encryptedInfo = new byte[0];
                    try {
                        encryptedInfo = result.getCryptoObject().getCipher().doFinal(
                                "plaintext - string".getBytes(Charset.defaultCharset()));
                        Log.d("MY_APP_TAG", "Encrypted information: " +
                                Arrays.toString(encryptedInfo));
                        textViewConfirmation.setVisibility(View.VISIBLE);
                        textViewEncryptedMessage.setVisibility(View.VISIBLE);
                        textViewEncryptedMessage.setText(Base64.encodeToString(encryptedInfo, 0 /* flags */)+" other method : "+ Arrays.toString(encryptedInfo));
                    } catch (BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }

                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "Authentication failed",
                        Toast.LENGTH_SHORT)
                        .show();
            }
        });
        return biometricPrompt;
    }

    private BiometricPrompt.PromptInfo createPromptInfo(){
        return new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric login for my app")
                .setSubtitle("Log in using your biometric credential")
//                .setConfirmationRequired(true)
                .setNegativeButtonText("Use app password")
//                         .setDeviceCredentialAllowed(true) // Allow PIN/pattern/password authentication.
                        // Also note that setDeviceCredentialAllowed and setNegativeButtonText are
                        // incompatible so that if you uncomment one you must comment out the other
                .build();
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with a fingerprint.
     *
     * @param keyName the name of the key to be created
     * @param invalidatedByBiometricEnrollment if `false` is passed, the created key will not be
     * invalidated even if a new fingerprint is enrolled. The default value is `true` - the key will
     * be invalidated if a new fingerprint is enrolled.
     */
    private void createKey(String keyName, Boolean invalidatedByBiometricEnrollment) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of enrolled
        // fingerprints has changed.
        try {
            keyStore.load(null);

            int keyProperties = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
            KeyGenParameterSpec.Builder keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                    keyName,
                    keyProperties
            )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    // Invalidate the keys if the user has registered a new biometric
                    // credential, such as a new fingerprint. Can call this method only
                    // on Android 7.0 (API level 24) or higher. The variable
                    // "invalidatedByBiometricEnrollment" is true by default.
                    .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
                    ;

            keyGenerator.init(keyGenParameterSpec.build());
            keyGenerator.generateKey();

        } catch (CertificateException | IOException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private SecretKey getSecretKey(String keyName) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null);
        return ((SecretKey)keyStore.getKey(keyName, null));
    }

    private  boolean initCipher(Cipher cipher, String keyName){
        try {
            cipher.init(Cipher.ENCRYPT_MODE,getSecretKey(keyName));
            return true;
        } catch (InvalidKeyException | KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return false;
    }
}
