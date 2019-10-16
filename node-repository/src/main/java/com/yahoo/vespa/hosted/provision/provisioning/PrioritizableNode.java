// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.provision.provisioning;

import com.yahoo.config.provision.NodeResources;
import com.yahoo.vespa.hosted.provision.Node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.yahoo.vespa.hosted.provision.provisioning.NodePrioritizer.ALLOCATABLE_HOST_STATES;

/**
 * A node with additional information required to prioritize it for allocation.
 *
 * @author smorgrav
 */
class PrioritizableNode implements Comparable<PrioritizableNode> {

    private static final NodeResources zeroResources =
            new NodeResources(0, 0, 0, 0, NodeResources.DiskSpeed.any);

    // TODO: Make immutable
    Node node;

    /** The free capacity on the parent of this node, before adding this node to it */
    private final NodeResources freeParentCapacity;

    /** The parent host (docker or hypervisor) */
    final Optional<Node> parent;

    /** True if the node is allocated to a host that should be dedicated as a spare */
    final boolean violatesSpares;

    /** True if this is a node that has been retired earlier in the allocation process */
    final boolean isSurplusNode;

    /** This node does not exist in the node repository yet */
    final boolean isNewNode;

    PrioritizableNode(Node node, NodeResources freeParentCapacity, Optional<Node> parent, boolean violatesSpares, boolean isSurplusNode, boolean isNewNode) {
        this.node = node;
        this.freeParentCapacity = freeParentCapacity;
        this.parent = parent;
        this.violatesSpares = violatesSpares;
        this.isSurplusNode = isSurplusNode;
        this.isNewNode = isNewNode;
    }

    /**
     * Compares two prioritizable nodes
     *
     * @return negative if first priority is higher than second node
     */
    @Override
    public int compareTo(PrioritizableNode other) {
        // First always pick nodes without violation above nodes with violations
        if (!this.violatesSpares && other.violatesSpares) return -1;
        if (!other.violatesSpares && this.violatesSpares) return 1;

        // Choose active nodes
        if (this.node.state() == Node.State.active && other.node.state() != Node.State.active) return -1;
        if (other.node.state() == Node.State.active && this.node.state() != Node.State.active) return 1;

        // Choose active node that is not retired first (surplus is active but retired)
        if (!this.isSurplusNode && other.isSurplusNode) return -1;
        if (!other.isSurplusNode && this.isSurplusNode) return 1;

        // Choose inactive nodes
        if (this.node.state() == Node.State.inactive && other.node.state() != Node.State.inactive) return -1;
        if (other.node.state() == Node.State.inactive && this.node.state() != Node.State.inactive) return 1;

        // Choose reserved nodes from a previous allocation attempt (the exist in node repo)
        if (this.isInNodeRepoAndReserved() && ! other.isInNodeRepoAndReserved()) return -1;
        if (other.isInNodeRepoAndReserved() && ! this.isInNodeRepoAndReserved()) return 1;

        // Choose ready nodes
        if (this.node.state() == Node.State.ready && other.node.state() != Node.State.ready) return -1;
        if (other.node.state() == Node.State.ready && this.node.state() != Node.State.ready) return 1;

        if (this.node.state() != other.node.state())
            throw new IllegalStateException("Nodes " + this.node + " and " + other.node + " have different states");

        // Choose nodes where host is in more desirable state
        int thisHostStatePri = this.parent.map(host -> ALLOCATABLE_HOST_STATES.indexOf(host.state())).orElse(-2);
        int otherHostStatePri = other.parent.map(host -> ALLOCATABLE_HOST_STATES.indexOf(host.state())).orElse(-2);
        if (thisHostStatePri != otherHostStatePri) return otherHostStatePri - thisHostStatePri;

        if (this.parent.isPresent() && other.parent.isPresent()) {
            int diskCostDifference = NodeResources.DiskSpeed.compare(this.parent.get().flavor().resources().diskSpeed(),
                                                                     other.parent.get().flavor().resources().diskSpeed());
            if (diskCostDifference != 0)
                return diskCostDifference;
        }

        int hostPriority = Double.compare(this.skewWithThis() - this.skewWithoutThis(),
                                          other.skewWithThis() - other.skewWithoutThis());
        if (hostPriority != 0) return hostPriority;

        // Choose cheapest node
        if (this.node.flavor().cost() < other.node.flavor().cost()) return -1;
        if (other.node.flavor().cost() < this.node.flavor().cost()) return 1;

        // All else equal choose hostname alphabetically
        return this.node.hostname().compareTo(other.node.hostname());
    }

    /** Returns the allocation skew of the parent of this before adding this node to it */
    double skewWithoutThis() { return skewWith(zeroResources); }

    /** Returns the allocation skew of the parent of this after adding this node to it */
    double skewWithThis() { return skewWith(node.flavor().resources()); }

    private double skewWith(NodeResources resources) {
        if (parent.isEmpty()) return 0;

        NodeResources all = anySpeed(parent.get().flavor().resources());
        NodeResources allocated = all.subtract(anySpeed(freeParentCapacity)).add(anySpeed(resources));

        return new Mean(allocated.vcpu() / all.vcpu(),
                        allocated.memoryGb() / all.memoryGb(),
                        allocated.diskGb() / all.diskGb())
                       .deviation();
    }

    /** We don't care about disk speed in calculations here */
    private NodeResources anySpeed(NodeResources resources) {
        return resources.withDiskSpeed(NodeResources.DiskSpeed.any);
    }

    private boolean isInNodeRepoAndReserved() {
        if (isNewNode) return false;
        return node.state().equals(Node.State.reserved);
    }

    @Override
    public String toString() {
        return node.id();
    }

    static class Builder {

        public final Node node;
        private NodeResources freeParentCapacity;
        private Optional<Node> parent = Optional.empty();
        private boolean violatesSpares;
        private boolean isSurplusNode;
        private boolean isNewNode;

        Builder(Node node) {
            this.node = node;
            this.freeParentCapacity = node.flavor().resources();
        }

        /** The free capacity of the parent, before adding this node to it */
        Builder withFreeParentCapacity(NodeResources freeParentCapacity) {
            this.freeParentCapacity = freeParentCapacity;
            return this;
        }

        Builder withParent(Node parent) {
            this.parent = Optional.of(parent);
            return this;
        }

        Builder withViolatesSpares(boolean violatesSpares) {
            this.violatesSpares = violatesSpares;
            return this;
        }

        Builder withSurplusNode(boolean surplusNode) {
            isSurplusNode = surplusNode;
            return this;
        }

        Builder withNewNode(boolean newNode) {
            isNewNode = newNode;
            return this;
        }
        
        PrioritizableNode build() {
            return new PrioritizableNode(node, freeParentCapacity, parent, violatesSpares, isSurplusNode, isNewNode);
        }
    }

    /** The mean and mean deviation (squared difference) of a bunch of numbers */
    private static class Mean {

        private double mean;
        private double deviation;

        private Mean(double ... numbers) {
            mean = Arrays.stream(numbers).sum() / numbers.length;
            deviation = Arrays.stream(numbers).map(n -> Math.pow(mean - n, 2)).sum() / numbers.length;
        }

        public double deviation() {  return deviation; }

    }

}
