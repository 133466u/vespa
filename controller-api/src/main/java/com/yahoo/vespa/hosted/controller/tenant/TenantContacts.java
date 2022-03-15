// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.controller.tenant;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Tenant contacts are targets of the notification system.  Sometimes they
 * are a person with an email address, other times they are a Slack channel,
 * IRC plugin, etc.
 *
 * @author ogronnesby
 */
public class TenantContacts {
    private final List<? extends Contact> contacts;

    public TenantContacts(List<? extends Contact> contacts) {
        this.contacts = List.copyOf(contacts);
    }

    public static TenantContacts empty() {
        return new TenantContacts(List.of());
    }

    public List<? extends Contact> all() {
        return contacts;
    }

    public boolean isEmpty() {
        return contacts.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TenantContacts that = (TenantContacts) o;
        return contacts.equals(that.contacts);
    }

    @Override
    public int hashCode() {
        return Objects.hash(contacts);
    }

    @Override
    public String toString() {
        return "TenantContacts{" +
                "contacts=" + contacts +
                '}';
    }

    public abstract static class Contact {
        private final List<Audience> audiences;

        public Contact(List<Audience> audiences) {
            this.audiences = List.copyOf(audiences);
            if (audiences.isEmpty()) throw new IllegalArgumentException("at least one notification activity must be enabled");
        }

        public List<Audience> audiences() { return audiences; }

        public abstract Type type();

        public abstract boolean equals(Object o);
        public abstract int hashCode();
        public abstract String toString();
    }

    public static class EmailContact extends Contact {
        private final String email;

        public EmailContact(List<Audience> audiences, String email) {
            super(audiences);
            this.email = email;
        }

        public String email() { return email; }

        @Override
        public Type type() {
            return Type.EMAIL;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            EmailContact that = (EmailContact) o;
            return email.equals(that.email);
        }

        @Override
        public int hashCode() {
            return Objects.hash(email);
        }

        @Override
        public String toString() {
            return "EmailContact{" +
                    "email='" + email + '\'' +
                    '}';
        }
    }

    public enum Type {
        EMAIL("email");

        private final String value;

        Type(String value) {
            this.value = value;
        }

        public String value() {
            return this.value;
        }

        public static Optional<Type> from(String value) {
            return Arrays.stream(Type.values()).filter(x -> x.value().equals(value)).findAny();
        }
    }

    public enum Audience {
        // tenant admin type updates about billing etc.
        TENANT("tenant"),

        // system notifications like deployment failures etc.
        NOTIFICATIONS("notifications");

        private final String value;

        Audience(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }

        public static Optional<Audience> from(String value) {
            return Arrays.stream(Audience.values()).filter((x -> x.value().equals(value))).findAny();
        }
    }
}
