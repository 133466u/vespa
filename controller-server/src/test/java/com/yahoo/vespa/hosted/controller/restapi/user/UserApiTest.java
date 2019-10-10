package com.yahoo.vespa.hosted.controller.restapi.user;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.config.provision.SystemName;
import com.yahoo.config.provision.TenantName;
import com.yahoo.vespa.hosted.controller.api.role.Role;
import com.yahoo.vespa.hosted.controller.restapi.ContainerTester;
import com.yahoo.vespa.hosted.controller.restapi.ControllerContainerCloudTest;
import org.junit.Test;

import java.io.File;
import java.util.Set;

import static com.yahoo.application.container.handler.Request.Method.DELETE;
import static com.yahoo.application.container.handler.Request.Method.POST;
import static com.yahoo.application.container.handler.Request.Method.PUT;
import static org.junit.Assert.assertEquals;

/**
 * @author jonmv
 */
public class UserApiTest extends ControllerContainerCloudTest {

    private static final String responseFiles = "src/test/java/com/yahoo/vespa/hosted/controller/restapi/user/responses/";
    private static final String pemPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                                               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuKVFA8dXk43kVfYKzkUqhEY2rDT9\n" +
                                               "z/4jKSTHwbYR8wdsOSrJGVEUPbS2nguIJ64OJH7gFnxM6sxUVj+Nm2HlXw==\n" +
                                               "-----END PUBLIC KEY-----\n";
    private static final String otherPemPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                                                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFELzPyinTfQ/sZnTmRp5E4Ve/sbE\n" +
                                                    "pDhJeqczkyFcT2PysJ5sZwm7rKPEeXDOhzTPCyRvbUqc2SGdWbKUGGa/Yw==\n" +
                                                    "-----END PUBLIC KEY-----\n";
    private static final String quotedPemPublicKey = pemPublicKey.replaceAll("\\n", "\\\\n");
    private static final String otherQuotedPemPublicKey = otherPemPublicKey.replaceAll("\\n", "\\\\n");


    @Test
    public void testUserManagement() {
        ContainerTester tester = new ContainerTester(container, responseFiles);
        assertEquals(SystemName.Public, tester.controller().system());
        Set<Role> operator = Set.of(Role.hostedOperator());
        ApplicationId id = ApplicationId.from("my-tenant", "my-app", "default");


        // GET at application/v4 root fails as it's not public read.
        tester.assertResponse(request("/application/v4/"),
                              accessDenied, 403);

        // GET at application/v4/tenant succeeds for operators.
        tester.assertResponse(request("/application/v4/tenant")
                                      .roles(operator),
                              "[]");

        // GET at application/v4/tenant is available also under the /api prefix.
        tester.assertResponse(request("/api/application/v4/tenant")
                                      .roles(operator),
                              "[]");

        // POST a tenant is not available to everyone.
        tester.assertResponse(request("/application/v4/tenant/my-tenant", POST)
                                      .data("{\"token\":\"hello\"}"),
                              accessDenied, 403);

        // POST a tenant is available to operators.
        tester.assertResponse(request("/application/v4/tenant/my-tenant", POST)
                                      .roles(operator)
                                      .user("administrator@tenant")
                                      .data("{\"token\":\"hello\"}"),
                              new File("tenant-without-applications.json"));

        // PUT a tenant is not available to anyone.
        tester.assertResponse(request("/application/v4/user/", PUT)
                                      .roles(operator),
                              "{\"error-code\":\"FORBIDDEN\",\"message\":\"Not authenticated or not a user.\"}", 403);

        // GET at user/v1 root fails as no access control is defined there.
        tester.assertResponse(request("/user/v1/"),
                              accessDenied, 403);

        // POST a hosted operator role is not allowed.
        tester.assertResponse(request("/user/v1/tenant/my-tenant", POST)
                                      .roles(Set.of(Role.administrator(id.tenant())))
                                      .data("{\"user\":\"evil@evil\",\"roleName\":\"hostedOperator\"}"),
                              "{\"error-code\":\"BAD_REQUEST\",\"message\":\"Malformed or illegal role name 'hostedOperator'.\"}", 400);

        // POST a tenant developer is available to the tenant owner.
        tester.assertResponse(request("/user/v1/tenant/my-tenant", POST)
                                      .roles(Set.of(Role.administrator(id.tenant())))
                                      .data("{\"user\":\"developer@tenant\",\"roles\":[\"developer\",\"reader\"]}"),
                              "{\"message\":\"user 'developer@tenant' is now a member of role 'developer' of 'my-tenant', role 'reader' of 'my-tenant'\"}");

        // POST a tenant admin is not available to a tenant developer.
        tester.assertResponse(request("/user/v1/tenant/my-tenant", POST)
                                      .roles(Set.of(Role.developer(id.tenant())))
                                      .data("{\"user\":\"developer@tenant\",\"roleName\":\"administrator\"}"),
                              accessDenied, 403);

        // POST a headless for a non-existent application fails.
        tester.assertResponse(request("/user/v1/tenant/my-tenant/application/my-app", POST)
                                      .roles(Set.of(Role.administrator(TenantName.from("my-tenant"))))
                                      .data("{\"user\":\"headless@app\",\"roleName\":\"headless\"}"),
                              "{\"error-code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"NullPointerException\"}", 500);

        // POST an application is allowed for a tenant developer.
        tester.assertResponse(request("/application/v4/tenant/my-tenant/application/my-app", POST)
                                      .user("developer@tenant")
                                      .roles(Set.of(Role.developer(id.tenant()))),
                              new File("application-created.json"));

        // POST an application is not allowed under a different tenant.
        tester.assertResponse(request("/application/v4/tenant/other-tenant/application/my-app", POST)
                                      .roles(Set.of(Role.administrator(id.tenant()))),
                              accessDenied, 403);

        // POST a tenant role is not allowed to an application.
        tester.assertResponse(request("/user/v1/tenant/my-tenant/application/my-app", POST)
                                      .roles(Set.of(Role.hostedOperator()))
                                      .data("{\"user\":\"developer@app\",\"roleName\":\"developer\"}"),
                              "{\"error-code\":\"BAD_REQUEST\",\"message\":\"Malformed or illegal role name 'developer'.\"}", 400);

        // GET tenant role information is available to readers.
        tester.assertResponse(request("/user/v1/tenant/my-tenant")
                             .roles(Set.of(Role.reader(id.tenant()))),
                              new File("tenant-roles.json"));

        // GET application role information is available to tenant administrators.
        tester.assertResponse(request("/user/v1/tenant/my-tenant/application/my-app")
                                      .roles(Set.of(Role.administrator(id.tenant()))),
                              new File("application-roles.json"));

        // GET application role information is available also under the /api prefix.
        tester.assertResponse(request("/api/user/v1/tenant/my-tenant/application/my-app")
                                      .roles(Set.of(Role.administrator(id.tenant()))),
                              new File("application-roles.json"));

        // POST a pem deploy key
        tester.assertResponse(request("/application/v4/tenant/my-tenant/application/my-app/key", POST)
                                      .roles(Set.of(Role.developer(id.tenant())))
                                      .data("{\"key\":\"" + pemPublicKey + "\"}"),
                              new File("first-deploy-key.json"));

        // POST a pem developer key
        tester.assertResponse(request("/application/v4/tenant/my-tenant/key", POST)
                                      .user("joe@dev")
                                      .roles(Set.of(Role.developer(id.tenant())))
                                      .data("{\"key\":\"" + pemPublicKey + "\"}"),
                              new File("first-developer-key.json"));

        // POST the same pem developer key for a different user is forbidden
        tester.assertResponse(request("/application/v4/tenant/my-tenant/key", POST)
                                      .user("operator@tenant")
                                      .roles(Set.of(Role.developer(id.tenant())))
                                      .data("{\"key\":\"" + pemPublicKey + "\"}"),
                              "{\"error-code\":\"BAD_REQUEST\",\"message\":\"Key "+  quotedPemPublicKey + " is already owned by joe@dev\"}",
                              400);

        // POST in a different pem developer key
        tester.assertResponse(request("/application/v4/tenant/my-tenant/key", POST)
                                      .user("developer@tenant")
                                      .roles(Set.of(Role.developer(id.tenant())))
                                      .data("{\"key\":\"" + otherPemPublicKey + "\"}"),
                              new File("both-developer-keys.json"));

        // GET tenant information with keys
        tester.assertResponse(request("/application/v4/tenant/my-tenant/")
                                      .roles(Set.of(Role.reader(id.tenant()))),
                              new File("tenant-with-keys.json"));

        // DELETE a pem developer key
        tester.assertResponse(request("/application/v4/tenant/my-tenant/key", DELETE)
                                      .roles(Set.of(Role.developer(id.tenant())))
                                      .data("{\"key\":\"" + pemPublicKey + "\"}"),
                              new File("second-developer-key.json"));

        // DELETE an application is available to developers.
        tester.assertResponse(request("/application/v4/tenant/my-tenant/application/my-app", DELETE)
                             .roles(Set.of(Role.developer(id.tenant()))),
                              "{\"message\":\"Deleted application my-tenant.my-app\"}");

        // DELETE a tenant role is available to tenant admins.
        // DELETE the developer role clears any developer key.
        tester.assertResponse(request("/user/v1/tenant/my-tenant", DELETE)
                                      .roles(Set.of(Role.administrator(id.tenant())))
                                      .data("{\"user\":\"developer@tenant\",\"roleName\":\"developer\"}"),
                              "{\"message\":\"user 'developer@tenant' is no longer a member of role 'developer' of 'my-tenant'\"}");

        // DELETE the last tenant owner is not allowed.
        tester.assertResponse(request("/user/v1/tenant/my-tenant", DELETE)
                             .roles(operator)
                             .data("{\"user\":\"administrator@tenant\",\"roleName\":\"administrator\"}"),
                              "{\"error-code\":\"BAD_REQUEST\",\"message\":\"Can't remove the last administrator of a tenant.\"}", 400);

        // DELETE the tenant is available to the tenant owner.
        tester.assertResponse(request("/application/v4/tenant/my-tenant", DELETE)
                                      .roles(Set.of(Role.tenantOwner(id.tenant()))),
                              new File("tenant-without-applications.json"));
    }

}
