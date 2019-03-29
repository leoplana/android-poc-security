package cryptpoc.model;

public class KeyPairResponse {

	private String publicKey;
	private String privateKey;
	private String symmetricalKey;
	private String plainSymmetricalKey;

	public KeyPairResponse(String publicKey, String privateKey) {
		super();
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public KeyPairResponse() {
		super();
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public String getSymmetricalKey() {
		return symmetricalKey;
	}

	public void setSymmetricalKey(String symmetricalKey) {
		this.symmetricalKey = symmetricalKey;
	}

	public String getPlainSymmetricalKey() {
		return plainSymmetricalKey;
	}

	public void setPlainSymmetricalKey(String plainSymmetricalKey) {
		this.plainSymmetricalKey = plainSymmetricalKey;
	}

}
