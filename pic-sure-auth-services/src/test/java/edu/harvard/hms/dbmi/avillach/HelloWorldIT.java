package edu.harvard.hms.dbmi.avillach;

import edu.harvard.hms.dbmi.avillach.auth.utils.HttpClientUtil;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.UserInfo;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class HelloWorldIT {
    private static String endpointUrl;

    @BeforeClass
    public static void beforeClass() {
        endpointUrl = System.getProperty("service.url");
    }

    @Test
    public void testPing() throws Exception {
//        WebClient client = WebClient.create(endpointUrl + "/hello/echo/SierraTangoNevada");
//        Response r = client.accept("text/plain").get();
//        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
//        String value = IOUtils.toString((InputStream)r.getEntity());
//        assertEquals("SierraTangoNevada", value);
    }

    @Test
    public void testJsonRoundtrip() throws Exception {
//        List<Object> providers = new ArrayList<Object>();
//        providers.add(new org.codehaus.jackson.jaxrs.JacksonJsonProvider());
//        JsonBean inputBean = new JsonBean();
//        inputBean.setVal1("Maple");
//        WebClient client = WebClient.create(endpointUrl + "/hello/jsonBean", providers);
//        Response r = client.accept("application/json")
//            .type("application/json")
//            .post(inputBean);
//        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
//        MappingJsonFactory factory = new MappingJsonFactory();
//        JsonParser parser = factory.createJsonParser((InputStream)r.getEntity());
//        JsonBean output = parser.readValueAs(JsonBean.class);
//        assertEquals("Maple", output.getVal2());
    }
    
}
