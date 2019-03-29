package cryptpoc;

import java.util.AbstractMap;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.HashMap;

import com.fasterxml.jackson.databind.ObjectMapper;

import cryptpoc.utils.AESUtils;
import cryptpoc.utils.RSAUtils;

public class AndroidPoc {

	public static void main(String[] args) throws Exception {

		// Both attrs will be returned from server (1st request)
		// Server response { pk : pkGotFromServer, cid: cidGotFromServer}
		HashMap<String, String> responseFromFirstService = new HashMap<>();
		responseFromFirstService.put("pk",
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl1ePXVOSt7/BksdQBlQrfZbLpJB/URdFw6OiYY0nY7hW+xVTsfGPpppLbt8tatlJrwosUjd94cdDFzs4ryxrk01+b1HuKJivbxealdYRLtXMeRD/mUguOVEsTdcNZ3cpmg4OhL+3Rju3jUgK1sK5xx8Egkal/mxVCX7u6FNMeTJGZFcefCiftz9bGjDzpWnpBL2v4+IdIGe0XOUlYkKD4w+jla06saaYVR0SdFPquOgPNHSaCPovhwdv14Mertil6sAQ/QYLjtShv7Ki8Xdwl7Q4cLgAXcuvlvByHtFh7DDFGpdtZNjslT6R7QWYNuGp6H6JAglKDlM2VwD7nX2TzwIDAQAB");
		responseFromFirstService.put("cid",
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiQmVhcmVyIiwiaWF0IjoxNTUzNzA0MDI2LCJpYXRNcyI6MTU1MzcwNDAyNjk5Miwic2VxIjowLCJleHAiOjE1NTM3MDQ2MjYsImF1ZCI6IjY3NmE5MDYwMzIxYTAxMzc1NTE5MDAwZDNhYzA2ZDc2IiwiaXNzIjoiWnVwLm1lIEdhdGV3YXkiLCJzdWIiOiIyOWE3NWZmMC01MGFkLTExZTktYmM0MC0wMjlhY2NkMGNhMDYiLCJqdGkiOiIyOWE3ODcwMC01MGFkLTExZTktYmM0MC0xMzZkMTE2MTM4OWQifQ.KIQZfb0oT9wlV__ynBdn_Jze2iuyzk5sqwi64FvwLOg");

		System.out.println(String.format("Received from 1st service: \n%s\n\n",
				new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(responseFromFirstService)));

		// Generates random AES pass, encrypt with the pk received then send it
		// back
		String randomAesIvPass = AESUtils.generateIvPass();
		String encryptedRandomAesIvPass = RSAUtils.encrypt(responseFromFirstService.get("pk"), randomAesIvPass);

		// Send it back to 2nd service
		HashMap<String, String> requestToSecondService = new HashMap<>();
		requestToSecondService.put("s", encryptedRandomAesIvPass);
		requestToSecondService.put("cid",
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiQmVhcmVyIiwiaWF0IjoxNTUzNzA0MDI2LCJpYXRNcyI6MTU1MzcwNDAyNjk5Miwic2VxIjowLCJleHAiOjE1NTM3MDQ2MjYsImF1ZCI6IjY3NmE5MDYwMzIxYTAxMzc1NTE5MDAwZDNhYzA2ZDc2IiwiaXNzIjoiWnVwLm1lIEdhdGV3YXkiLCJzdWIiOiIyOWE3NWZmMC01MGFkLTExZTktYmM0MC0wMjlhY2NkMGNhMDYiLCJqdGkiOiIyOWE3ODcwMC01MGFkLTExZTktYmM0MC0xMzZkMTE2MTM4OWQifQ.KIQZfb0oT9wlV__ynBdn_Jze2iuyzk5sqwi64FvwLOg");
		// Sends it with body : { "cid" : cidToBeSent, "s" : secretToBeSent }

		System.out.println(String.format("Sending back my secret pass: \n%s\n\n",
				new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(requestToSecondService)));

		HashMap<String, Object> request = new HashMap<>();
		String iv = randomAesIvPass.split(":")[0];
		String key = randomAesIvPass.split(":")[1];

		// Then uses generated AES key
		SimpleEntry<String, String> cidHeader = new AbstractMap.SimpleEntry<String, String>("cid",
				responseFromFirstService.get("cid"));
		HashMap<String, String> body = new HashMap<>();
		body.put("user", AESUtils.encrypt(iv, key, "56496980403"));
		body.put("password", AESUtils.encrypt(iv, key, "switchrules"));
		request.put("headers", Arrays.asList(cidHeader));
		request.put("body", body);

		System.out.println(String.format("Next request may be hidden : \n%s",
				new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(request)));

	}

}
