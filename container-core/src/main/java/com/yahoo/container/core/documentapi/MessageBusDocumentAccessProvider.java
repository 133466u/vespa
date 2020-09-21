package com.yahoo.container.core.documentapi;

import com.google.inject.Inject;
import com.yahoo.component.AbstractComponent;
import com.yahoo.container.di.componentgraph.Provider;
import com.yahoo.document.config.DocumentmanagerConfig;
import com.yahoo.document.select.parser.ParseException;
import com.yahoo.documentapi.AsyncParameters;
import com.yahoo.documentapi.AsyncSession;
import com.yahoo.documentapi.DocumentAccess;
import com.yahoo.documentapi.DocumentAccessParams;
import com.yahoo.documentapi.SubscriptionParameters;
import com.yahoo.documentapi.SubscriptionSession;
import com.yahoo.documentapi.SyncParameters;
import com.yahoo.documentapi.SyncSession;
import com.yahoo.documentapi.VisitorDestinationParameters;
import com.yahoo.documentapi.VisitorDestinationSession;
import com.yahoo.documentapi.VisitorParameters;
import com.yahoo.documentapi.VisitorSession;
import com.yahoo.documentapi.messagebus.MessageBusDocumentAccess;
import com.yahoo.documentapi.messagebus.MessageBusParams;
import com.yahoo.documentapi.messagebus.loadtypes.LoadTypeSet;
import com.yahoo.vespa.config.content.LoadTypeConfig;

/**
 * Lets a lazily initialised DocumentAccess forwarding to a real MessageBusDocumentAccess be injected in containers.
 *
 * @author jonmv
 */
public class MessageBusDocumentAccessProvider extends AbstractComponent implements Provider<DocumentAccess> {

    private final DocumentAccess access;

    @Inject
    // TODO jonmv: Have Slobrok and RPC config injected as well.
    public MessageBusDocumentAccessProvider(DocumentmanagerConfig documentmanagerConfig, LoadTypeConfig loadTypeConfig) {
        this.access = new LazyForwardingMessageBusDocumentAccess(documentmanagerConfig, loadTypeConfig);
    }

    @Override
    public DocumentAccess get() {
        return access;
    }

    @Override
    public void deconstruct() {
        access.shutdown();
    }


    private static class LazyForwardingMessageBusDocumentAccess extends DocumentAccess {

        private final DocumentmanagerConfig documentmanagerConfig;
        private final LoadTypeConfig loadTypeConfig;
        private final Object monitor = new Object();

        private DocumentAccess delegate = null;
        private boolean shutDown = false;

        public LazyForwardingMessageBusDocumentAccess(DocumentmanagerConfig documentmanagerConfig,
                                                      LoadTypeConfig loadTypeConfig) {
            super(new DocumentAccessParams().setDocumentmanagerConfig(documentmanagerConfig));
            this.documentmanagerConfig = documentmanagerConfig;
            this.loadTypeConfig = loadTypeConfig;
        }

        private DocumentAccess delegate() {
            synchronized (monitor) {
                if (delegate == null) {
                    if (shutDown)
                        throw new IllegalStateException("This document access has been shut down");

                    delegate = new MessageBusDocumentAccess((MessageBusParams) new MessageBusParams(new LoadTypeSet(loadTypeConfig)).setDocumentmanagerConfig(documentmanagerConfig));
                }
                return delegate;
            }
        }

        @Override
        public void shutdown() {
            synchronized (monitor) {
                super.shutdown();
                shutDown = true;
                if (delegate != null)
                    delegate.shutdown();
            }
        }

        @Override
        public SyncSession createSyncSession(SyncParameters parameters) {
            return delegate().createSyncSession(parameters);
        }

        @Override
        public AsyncSession createAsyncSession(AsyncParameters parameters) {
            return delegate().createAsyncSession(parameters);
        }

        @Override
        public VisitorSession createVisitorSession(VisitorParameters parameters) throws ParseException {
            return delegate().createVisitorSession(parameters);
        }

        @Override
        public VisitorDestinationSession createVisitorDestinationSession(VisitorDestinationParameters parameters) {
            return delegate().createVisitorDestinationSession(parameters);
        }

        @Override
        public SubscriptionSession createSubscription(SubscriptionParameters parameters) {
            return delegate().createSubscription(parameters);
        }

        @Override
        public SubscriptionSession openSubscription(SubscriptionParameters parameters) {
            return delegate().openSubscription(parameters);
        }

    }

}
