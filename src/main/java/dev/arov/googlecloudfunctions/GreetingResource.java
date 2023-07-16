package dev.arov.googlecloudfunctions;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;

@Path("/hello")
public class GreetingResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        return "hello";
    }

    @Path("/{name}")
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public String hello(@PathParam("name") String name) {
        return "hello " + name + "!!!";
    }

    @POST
    @Path("empty")
    public void empty() {
    }

    @GET
    @Path("error")
    public void error() {
        throw new RuntimeException("Oups!");
    }

}
