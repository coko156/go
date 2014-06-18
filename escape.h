// escape.h -- Go frontend escape analysis.    -*- C++ -*-

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GO_ESCAPE_H
#define GO_ESCAPE_H

class Typed_identifier;
class Field_reference_expression;
class Expression;
class Call_expression;
class Expression_list;
class Named_object;
class Statement;
class Escape_analysis_info;
class Escape_analysis_object;

// Escape analysis information about the Go program.

// This module implements an escape analysis based on the one described in
// "Escape Analysis for Java" by Choi et. al in OPSLA'99.
// Escape_analysis implements the flow insensitive version with unbounded field
// references.

// In this variant we only care about references escaping out of their
// functional scope, and not escaping to different goroutines (threads).
// We assume, by default, that objects passed to interface methods always
// escape. This way we avoid a whole program points-to analysis.

// Uses a simple shape abstraction for slices, maps and arrays. Arrays have
// a single field that abstracts all their contents. Maps have also a single
// field that abstracts their contents which are values and keys. Slices are
// just references to arrays.


// Escape_analysis builds a connection graph, consisting of two basic
// types of nodes: references and objects.
// Conceptually the connection graph is a directed bipartite graph.
// Reference nodes only have edges to objects (this are called pointsto edges),
// and objects only have edges to references (which are called field edges).
// The actual graph has a third type of edge from references to references
// to avoid propagating pointsto edges on construction.
// Objects pointed by pointer variables have a special field * (with field index
// -1). A concrete object might be represented by more than one abstract node.
//
// Object nodes are created in three situations:
//	1. an explicit allocation via new or make.
//	2. a field access with previously empty pointsto set (phantom node)
//	3. taking the address of a variable

// Phantom nodes represent objects that are pointed by a reference whose
// contents are not known. Typically fields of parameter objects point to
// objects that are not known in advance. When the pointsto set of a reference
// is computed, if its result is empty, a phantom object is created to abstract
// the unknown objects a reference might point to.

// A connection graph has the following property. If an object o created
// at a particular site can be assigned to particular variable v, there exists
// abstract nodes representing o. This way deciding whether (and how) an
// allocation escapes is translated into computing reachability in the graph.

// Theoretical size of the graph:
// Each expression has at most 1 reference node, one (implicit) field node and
// at most 2 object nodes (in the case of a slice or map) this gives an upper
// bound of 4*number of expressions.
// There is only need to keep one graph (current function) at a time.


class Escape_analysis
{
 public:
  enum Object_type
    {
      OBJECT,		// Allocations.
      PARAMETER,	// Formal parameters.
      REFVAR,		// Local variables (includes temps).
      GLOBAL,		// Global variables.
      RETURN,		// Return node.
      PHANTOM,		// An unknown node pointed by some object field,
      FIELD		// A node representing the field of an object.
    };

  enum Escape_level
    {
      NO_ESCAPE,	// Does not escape.
      ARG_ESCAPE,	// Escapes through an argument or return.
      GLOBAL_ESCAPE	// Escapes through a global.
    };

  // Construction.
  Escape_analysis()
    : escape_info_map_()
  { }

  // Destructor.
  ~Escape_analysis();

  // Perform the escape analysis.
  static void
  perform(Gogo*);

  // Compute function list.
  void
  compute_functions_to_process(Gogo*);

  // Compute the analysis results for the current package
  void
  compute_analysis_results();

  // Initialize the escape analysis info for a function.
  Escape_analysis_info*
  initialize_escape_info(Named_object*);

  // Add a function to the set of functions to explore.
  void
  add_function(Named_object* no)
  { this->functions_.insert(no); }

  // Returns whether a function is deemed safe, i.e. not globally leaking
  // objects reachable by parameters.
  bool is_safe_function(Named_object* no)
  { return this->safe_functions_.count(no) != 0; }

  // Add a call.
  void
  add_caller_callee(Named_object* caller, const Named_object* callee)
  {
    this->caller_map[callee].insert(caller);
  }

 private:
  // Typedef for the escape info map.
  typedef std::map<Named_object*, Escape_analysis_info*> Escape_info_map;

  typedef std::set<Named_object*> Named_object_set;

  typedef std::map<const Named_object*, Named_object_set> Caller_map;

  typedef std::vector<Named_object*> Named_object_vector;

  // Escape analysis info for each function.
  Escape_info_map escape_info_map_;

  // Safe functions. This is the most simple summary for functions.
  // a safe function does not leak anything pointed by a parameter to
  // the heap. A call to a safe function only needs to alias
  // the actual parameters.
  // TODO: Refine if necessary.
  Named_object_set safe_functions_;

  // The original set of functions;
  Named_object_set functions_;

  // Topological sorted list of functions
  Named_object_vector sorted_functions_;

  // The set of edges.
  Caller_map caller_map;

  // keeps track of the scope depth to annotate created objects.
  uint current_scope_depth_;
};

class Escape_analysis_info
{
 public:
  // Constructor.
  Escape_analysis_info(Escape_analysis* escape_analysis)
    : escape_analysis_(escape_analysis), updated_(false), aborted_(false)
  { }

  // Destuctor.
  ~Escape_analysis_info();

  // Has this information been updated? Used for the fixpoint
  // computation.
  bool
  updated()
  { return this->updated_; }

  // Set/Reset as updated.
  void
  set_updated(bool val = true)
  { this->updated_ = val; }

  // Has this information been aborted?
  bool
  aborted()
  { return this->aborted_; }

  // Set as aborted.
  void
  abort_analysis()
  { this->aborted_ = true; }

  // Add an allocation site.
  Escape_analysis_object*
  process_allocation(Expression*, source_location);

  // Process an address of expression. Called to process the & unary operation
  // on outer = &(inner).
  Escape_analysis_object*
  process_address_of(Expression* outer, Expression* inner);

  // Process a dereference expression. Called to process a field reference
  // expression on outer = inner.field_index.
  Escape_analysis_object*
  process_field_reference(Expression* outer, Expression* inner,
			  int field_index);

  // Returns the reference object for a named object (i.e. a variable).
  // The second parameter expression can be NULL and is only
  // used to label a second phantom object (pointer by a parameter).
  Escape_analysis_object*
  get_ea_object_for_variable(const Named_object*, Expression* expr);

  // Returns the reference object for a temporary statement.
  // Parameter expr is used only to label the object.
  Escape_analysis_object*
  get_ea_object_for_temporary_statement(const Temporary_statement*,
					Expression* expr);

  // Returns the reference object for an expression.
  Escape_analysis_object*
  get_ea_object_for_expression(Expression* expr);

  // Process a constant literal of a basic type.
  Escape_analysis_object*
  process_constant(Expression* const);

  // Process a call expression. This function handles a function call.
  // The parameters have the form call = fn(args). The last parameter is_void
  // specifies whether the function has a return value or not.
  Escape_analysis_object*
  process_call(const Named_object* fn_name, Call_expression* call,
	       Expression_list* args, bool is_void);

  // Process a go statement. This function handles a go statement. The
  // parameters represent an expression of the form fn(args).
  void
  process_go_statement(Expression* fn, Expression_list* args);

  // Process a nested function definition. This function handles the definition
  // of a nested function. Expr is the func_expression and closure is an
  // expression representing the closure. For now the closure is considered
  // as a parameter.
  Escape_analysis_object*
  process_function_reference(Expression* expr, Expression* closure);

  // Process the creation of a slice object. Used for Array_index_expression
  // when obtaining a slice from an array as in outer = inner[:].
  Escape_analysis_object*
  process_slice_creation(Expression* outer, Expression* inner);

  // Process the access to a slice element, as in outer = inner[_].
  // NOTE: Index is ignored, all elements are collapsed into the
  // field -1.
  Escape_analysis_object*
  process_slice_access(Expression* outer, Expression* inner);

  // Process a receive expression. (expr = <-channel)
  Escape_analysis_object*
  process_receive(Expression* expr, Expression* channel);

  // Process a send expression.(channel <- expr)
  void
  process_send(Expression* channel, Expression* expr);

  // Process an interface field reference as in outer = inner.field_name.
  Escape_analysis_object*
  process_interface_field_reference(Expression* outer, Expression* inner,
				    std::string& field_name);

  // Process a call result expression as ins outer = index@inner
  Escape_analysis_object*
  process_call_result(Expression* outer, Expression* inner, unsigned int index);

  // Implements the analysis rule for lhs = rhs.
  void
  variable_assignment_rule(Escape_analysis_object* lhs,
			   Escape_analysis_object* rhs);

  // Implements the analysis rule for lhs.field_index = rhs.
  void
  field_assignment_rule(Escape_analysis_object* lhs, int field_index,
			Escape_analysis_object* rhs);

  // Process constructions of many types. We only care about the expression and
  // its parameters of the form outer = T{args}
  Escape_analysis_object*
  process_construction(Expression* outer, Expression_list* pars,
		       bool collapse_fields);

  // Process constructions of slices and maps. Processes expressions of the
  // form outer = []...{args }
  Escape_analysis_object*
  process_container_construction(Expression* outer, Expression_list* pars);

  // Process a a conversion from a flat type to an interface, outer = (T)(inner)
  // Behaves like an allocation and a variable assignment.
  Escape_analysis_object*
  process_convert_flat_to_interface(Expression* outer, Expression* inner);

  // Makes the x to be defered to field labelled f in all objects that
  // y points to. y_f_exp is the expression representing y.f and is used
  // only to label a phantom object that might be created in the process.
  void
  defer_to_field(Escape_analysis_object* x, Escape_analysis_object* y, int f,
		 Expression* y_f_exp);

  // Dump info to stream.
  void
  dump_to_stream(std::ostream&);

  // Dump info to stream in dot format.
  void
  dump_to_stream_as_dot(std::ostream&);

  // Propagate the escape level through the graph by doing
  // reachability. It is done in two passes. The first reachability pass
  // starts from all the objects that are already marked as GLOBAL_ESCAPE. The
  // second pass starts from all objects that are marked ARG_ESCAPE.
  void
  propagate_escape_level();

  // Make a new analysis object associated to a named object.
  Escape_analysis_object*
  make_object_for_named_object(Escape_analysis::Object_type,
			       const Named_object*,
			       Escape_analysis::Escape_level =
				Escape_analysis::NO_ESCAPE);


  // Make a new analysis object associated to an expression.
  Escape_analysis_object*
  make_object_for_expression(Escape_analysis::Object_type, Expression*,
			     Escape_analysis::Escape_level =
			      Escape_analysis::NO_ESCAPE);

  // Make a new analysis object to represent a field.
  Escape_analysis_object*
  make_field_object(Escape_analysis_object* parent);

  // Report results as errors.
  void
  report_as_errors();

  // Propagate the analysis results to the ast nodes.
  void
  propagate_analysis_results();

  // Whether this connection graph has anything reachable from parameters or
  // returns that escapes to a global variable.
  bool
  is_safe_function();

  // Add a phantom object.
  Escape_analysis_object*
  add_phantom(Expression*,
	      Escape_analysis::Escape_level = Escape_analysis::NO_ESCAPE,
	      Escape_analysis::Object_type = Escape_analysis::PHANTOM);

  // Add a phantom object.
  Escape_analysis_object*
  add_phantom(const Named_object*,
	      Escape_analysis::Escape_level = Escape_analysis::NO_ESCAPE,
	      Escape_analysis::Object_type = Escape_analysis::PHANTOM);

  // Process an unsafe type cast.
  Escape_analysis_object*
  process_unsafe_conversion(Expression*);

 private:
  // Make a new analysis object.
  Escape_analysis_object*
  make_object(Escape_analysis::Object_type, const Named_object*, Expression*,
	      Escape_analysis::Escape_level);

  // Process an unsafe call expression.
  Escape_analysis_object*
  process_unsafe_call(Expression*, Expression_list* args, bool is_void);

  // Process a safe call expression.
  Escape_analysis_object*
  process_safe_call(Expression*, Expression_list* args, bool is_void);

  // Propagate escape level throughout the nodes.
  void
  propagate_escape_level(Escape_analysis::Escape_level);

  // Add an allocation site.
  Escape_analysis_object*
  get_ea_object_for_allocation(source_location, Expression*);

  // Add a reference variable.
  Escape_analysis_object*
  add_reference(Expression* expr, Statement* stm);

  typedef std::map<const Expression*, Escape_analysis_object*> Expression_map;
  typedef std::map<const Named_object*, Escape_analysis_object*>
    Named_object_map;
  typedef std::map<source_location, Escape_analysis_object*>
    Location_object_map;
  typedef std::map<const Temporary_statement*, Escape_analysis_object*>
    Temporary_object_map;

  // Vector of analysis objects.
  std::vector<Escape_analysis_object*> objects_;

  // Map from expressions to analysis objects (references).
  Expression_map expression_map_;

  // Maps Named_objects to analysis objects.
  Named_object_map named_object_references_map_;

  // Contains allocations, parameter placeholders and phantom objects.
  // We create at most 1 phantom object per expression.
  Expression_map expr_object_map_;

  // Contains allocations, parameter placeholders and phantom objects.
  // We create at most 1 phantom object per expression.
  Named_object_map no_object_map_;

  // Contains allocations.
  // We create at most 1 allocation object per source_location.
  Location_object_map location_object_map_;

  // Contains temporary references.
  // 1 reference per temporary statement.
  Temporary_object_map temporary_reference_map;

  // Link to parent.
  Escape_analysis* escape_analysis_;

  // Set if the graph has been updated.
  // Used to check whether the fixpoint has been reached.
  bool updated_;

  // Set if the analysis has been aborted.
  bool aborted_;
};


#endif // !defined(GO_ESCAPE_H)
