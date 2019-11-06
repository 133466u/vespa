// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.searchlib.rankingexpression.rule;

import com.google.common.annotations.Beta;
import com.yahoo.searchlib.rankingexpression.Reference;
import com.yahoo.searchlib.rankingexpression.evaluation.Context;
import com.yahoo.searchlib.rankingexpression.evaluation.TensorValue;
import com.yahoo.searchlib.rankingexpression.evaluation.Value;
import com.yahoo.tensor.Tensor;
import com.yahoo.tensor.TensorAddress;
import com.yahoo.tensor.TensorType;
import com.yahoo.tensor.evaluation.EvaluationContext;
import com.yahoo.tensor.evaluation.TypeContext;
import com.yahoo.tensor.functions.PrimitiveTensorFunction;
import com.yahoo.tensor.functions.TensorFunction;
import com.yahoo.tensor.functions.ToStringContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A node which performs a tensor function
 *
 * @author bratseth
 */
@Beta
public class TensorFunctionNode extends CompositeNode {

    private final TensorFunction function;

    public TensorFunctionNode(TensorFunction function) {
        this.function = function;
    }

    /** Returns the tensor function wrapped by this */
    public TensorFunction function() { return function; }

    @Override
    public List<ExpressionNode> children() {
        return function.arguments().stream()
                                           .map(this::toExpressionNode)
                                           .collect(Collectors.toList());
    }

    private ExpressionNode toExpressionNode(TensorFunction f) {
        if (f instanceof TensorFunctionExpressionNode)
            return ((TensorFunctionExpressionNode)f).expression;
        else
            return new TensorFunctionNode(f);
    }

    @Override
    public CompositeNode setChildren(List<ExpressionNode> children) {
        List<TensorFunction> wrappedChildren = children.stream()
                                                        .map(TensorFunctionExpressionNode::new)
                                                        .collect(Collectors.toList());
        return new TensorFunctionNode(function.withArguments(wrappedChildren));
    }

    @Override
    public StringBuilder toString(StringBuilder string, SerializationContext context, Deque<String> path, CompositeNode parent) {
        // Serialize as primitive
        return string.append(function.toPrimitive().toString(new ExpressionNodeToStringContext(context, path, this)));
    }

    @Override
    public TensorType type(TypeContext<Reference> context) { return function.type(context); }

    @Override
    public Value evaluate(Context context) {
        return new TensorValue(function.evaluate(context));
    }

    public static TensorFunctionExpressionNode wrap(ExpressionNode node) {
        return new TensorFunctionExpressionNode(node);
    }

    public static Map<TensorAddress, Function<EvaluationContext<?>, Double>> wrap(Map<TensorAddress, ExpressionNode> nodes) {
        Map<TensorAddress, Function<EvaluationContext<?>, Double>> closures = new LinkedHashMap<>();
        for (var entry : nodes.entrySet())
            closures.put(entry.getKey(), new ExpressionClosure(entry.getValue()));
        return closures;
    }

    public static List<Function<EvaluationContext<?>, Double>> wrap(List<ExpressionNode> nodes) {
        List<Function<EvaluationContext<?>, Double>> closures = new ArrayList<>();
        for (var entry : nodes)
            closures.add(new ExpressionClosure(entry));
        return closures;
    }

    private static class ExpressionClosure implements java.util.function.Function<EvaluationContext<?> , Double> {

        private final ExpressionNode expression;

        public ExpressionClosure(ExpressionNode expression) {
            this.expression = expression;
        }

        @Override
        public Double apply(EvaluationContext<?> context) {
            return expression.evaluate((Context)context).asDouble();
        }

        @Override
        public String toString() {
            return expression.toString();
        }

    }

    /**
     * A tensor function implemented by an expression.
     * This allows us to pass expressions as tensor function arguments.
     */
    public static class TensorFunctionExpressionNode extends PrimitiveTensorFunction {

        /** An expression which produces a tensor */
        private final ExpressionNode expression;

        public TensorFunctionExpressionNode(ExpressionNode expression) {
            this.expression = expression;
        }

        @Override
        public List<TensorFunction> arguments() {
            if (expression instanceof CompositeNode)
                return ((CompositeNode)expression).children().stream()
                                                             .map(TensorFunctionExpressionNode::new)
                                                             .collect(Collectors.toList());
            else
                return Collections.emptyList();
        }

        @Override
        public TensorFunction withArguments(List<TensorFunction> arguments) {
            if (arguments.size() == 0) return this;
            List<ExpressionNode> unwrappedChildren = arguments.stream()
                                                              .map(arg -> ((TensorFunctionExpressionNode)arg).expression)
                                                              .collect(Collectors.toList());
            return new TensorFunctionExpressionNode(((CompositeNode)expression).setChildren(unwrappedChildren));
        }

        @Override
        public PrimitiveTensorFunction toPrimitive() { return this; }

        @Override
        @SuppressWarnings("unchecked") // Generics awkwardness
        public <NAMETYPE extends TypeContext.Name> TensorType type(TypeContext<NAMETYPE> context) {
            return expression.type((TypeContext<Reference>)context);
        }

        @Override
        public <NAMETYPE extends TypeContext.Name> Tensor evaluate(EvaluationContext<NAMETYPE> context) {
            return expression.evaluate((Context)context).asTensor();
        }

        @Override
        public String toString() {
            return toString(ExpressionNodeToStringContext.empty);
        }

        @Override
        public String toString(ToStringContext c) {
            if (c instanceof ExpressionNodeToStringContext) {
                ExpressionNodeToStringContext context = (ExpressionNodeToStringContext) c;
                return expression.toString(new StringBuilder(),context.context, context.path, context.parent).toString();
            }
            else {
                return expression.toString();
            }
        }

    }

    /** Allows passing serialization context arguments through TensorFunctions */
    private static class ExpressionNodeToStringContext implements ToStringContext {

        final SerializationContext context;
        final Deque<String> path;
        final CompositeNode parent;

        public static final ExpressionNodeToStringContext empty = new ExpressionNodeToStringContext(new SerializationContext(),
                                                                                                    null,
                                                                                                    null);

        public ExpressionNodeToStringContext(SerializationContext context, Deque<String> path, CompositeNode parent) {
            this.context = context;
            this.path = path;
            this.parent = parent;
        }

    }

}
