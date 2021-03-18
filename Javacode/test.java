import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class test {
    static String json = "test.json";
    public static void main(String[] args) {
        JsonObject jsonObject = new JsonParser().parse(json).getAsJsonObject();

        String pageName = jsonObject.getAsJsonObject("proc").get("exepath").getAsString();
        System.out.println(pageName);

       /* JsonArray arr = jsonObject.getAsJsonArray("posts");
        for (int i = 0; i < arr.size(); i++) {
            String post_id = arr.get(i).getAsJsonObject().get("post_id").getAsString();
            System.out.println(post_id);
        }*/
    }
}