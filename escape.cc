// escape.cc -- Go frontend escape analysis.

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "go-system.h"

#include <queue>
#include <fstream>
#include <sstream>

#include "gogo.h"
#include "escape.h"
#include "types.h"
#include "expressions.h"
#include "statements.h"
#include "go-optimize.h"
#include "ast-dump.h"
#include "go-dump.h"

// The -fgo-optimize-stk flag to activate stack allocation optimization.
Go_optimize stack_alloc_optimization_flag("stk");

// The fgo-dump-esc flag to activate dumping of escape information as
// dot files.
Go_dump dump_escape_as_dot("esc");

// FIXME. Choose a better name for the flag
// The fgo-dump-escaserr flag to activate generating error messages with the
// escape information to be used by errchk.
Go_dump generate_error_from_escape("escaserr");

// Representation of an internal/external object.
class Escape_analysis_object
{
 public:
  // Constructor.
  Escape_analysis_object(Escape_analysis::Object_type object_type,
			 unsigned int id, Escape_analysis_info* escape_info,
			 const Named_object* no, Expression* expr,
			 Escape_analysis::Escape_level escape_level);

  // Object id internal to this analysis.
  long
  object_id()
  { return this->object_id_; }

  // Associated named object (can be NULL).
  const Named_object*
  object()
  { return this->object_; }

  // Returns the expression for this object if any.
  Expression*
  expression()
  { return this->expression_; }

  // Is this a reference node.
  bool
  is_reference()
  {
    return this->object_type_ != Escape_analysis::OBJECT
	   && this->object_type_ != Escape_analysis::PHANTOM
	   && this->object_type_ != Escape_analysis::PARAMETER;
  }

  // Is this a parameter reference node.
  bool
  is_parameter()
  { return this->object_type_ == Escape_analysis::PARAMETER; }

  // Is this a result reference node.
  bool
  is_result()
  { return this->object_type_ == Escape_analysis::RETURN; }

  // Is this a field node.
  bool
  is_field()
  { return this->object_type_ == Escape_analysis::FIELD; }

  // Is this a global variable.
  bool
  is_global()
  { return this->object_type_ == Escape_analysis::GLOBAL; }

  // Is this a reference.
  bool
  is_object()
  { return !this->is_reference(); }

  // Set the field id. -1 denotes *.
  void
  set_field_index(int id)
  { this->field_index_ = id; }

  // Get the field id. -1 denotes *.
  unsigned int
  field_index() const
  { return this->field_index_; }

  // Return the escape level of this object.
  Escape_analysis::Escape_level
  escape_level() const
  { return this->escape_level_; }

  // Sets the escape level of this object.
  void
  set_escape_level(Escape_analysis::Escape_level lvl);

  // Return the object_type of this object.
  Escape_analysis::Object_type
  object_type() const
  { return this->object_type_; }

  // Sets the object type of this object.
  void
  set_object_type(Escape_analysis::Object_type lvl);

  // Does the object have a pointer type?
  bool
  has_pointer();

  // Dump the object representation to a stream for debugging.
  void
  dump_to_stream(std::ostream& out, bool just_result = true);

  // Dump the object represetation to a stream in dot format for debugging.
  void
  dump_to_stream_as_dot(std::ostream& out);

  // Add a deferred edge to the connection graph.
  void
  add_defer_edge(Escape_analysis_object* object);

  // Add a field edge to the connection graph.
  void
  add_field_edge(Escape_analysis_object* object);

  // Add a points-to edge to the connection graph.
  void
  add_pointsto_edge(Escape_analysis_object* object);

 private:
  // We store Escape_analysis_object entries in a set, so we need a comparator.
  struct Escape_analysis_object_comparison
  {
    bool
    operator()(Escape_analysis_object* const& o1,
	       Escape_analysis_object* const& o2) const
    { return o1->object_id_ < o2->object_id_; }
  };

 public:
  typedef std::set<Escape_analysis_object*, Escape_analysis_object_comparison>
    Object_set;

  // Iterator on edges.
  typedef Object_set::iterator iterator;
  typedef Object_set::const_iterator const_iterator;

  // Compute the points to set.
  void
  compute_pointsto_set(Object_set* );

  // Compute the points to set, adding a phantom object if needed.
  // The phantom object will be associated with the expression.
  void
  compute_non_empty_pointsto_set(Object_set*, Expression* = NULL );

  iterator
  edges_begin()
  { return this->out_edges_.begin(); }

  const_iterator
  edges_begin() const
  { return this->out_edges_.begin(); }

  iterator
  edges_end()
  { return this->out_edges_.end(); }

  const_iterator
  edges_end() const
  { return this->out_edges_.end(); }

  bool
  edges_empty() const
  { return this->out_edges_.empty(); }

  Escape_analysis_object*
  get_field_index_reference(int field_index);

  bool
  report_as_error();

 private:
  Escape_analysis::Object_type object_type_;

  Escape_analysis::Escape_level escape_level_;

  // The object id.
  long object_id_;

  // The Named_object it represents if any.
  const Named_object* object_;

  // The expression it represents if any.
  Expression* expression_;

  // The outgoing edges.
  // FIXME. Replace by a more efficient representation for the graph if
  // necessary.
  Object_set out_edges_;

  // The field index (only for field objects)
  int field_index_;

  // The enclosing escape analysis info.
  Escape_analysis_info* escape_info_;
};

typedef Escape_analysis_object::Object_set  EA_object_set;
typedef std::vector<Escape_analysis_object*> EA_object_vector;

// The following classes build an approximation to the callgraph.
// This approximation might be completely erroneous, yet it won't affect
// the correctness of the escape analysis.
// It is only used to determine the order in which the functions are processed,
// try to analyse callees before callers.
// ANY CALLGRAPH IS SAFE.

// This class is used to traverse expressions to look for calls.
// The object is to build an abstraction of the call graph for the
// purpose of escape analysis.


class Call_graph_traverse_expressions : public Traverse
{
 public:
  Call_graph_traverse_expressions(
      Escape_analysis* escape_analysis_ctx, Named_object* function)
    : Traverse(traverse_expressions),
      escape_analysis_ctx_(escape_analysis_ctx), function_(function)
  { }

 protected:
  int
  expression(Expression**);

 private:
  // The dataflow information.
  Escape_analysis* escape_analysis_ctx_;
  // The function we are examining.
  Named_object* function_;
};

// Look for a call and register the caller/callee relation.

int
Call_graph_traverse_expressions::expression(Expression** expr)
{
  Call_expression* call_expression = (*expr)->call_expression();

  if (call_expression == NULL)
    return TRAVERSE_CONTINUE;

  const Named_object* called_function = call_expression->get_function_object();
  if (called_function != NULL)
    {
      // this is a function call to a known function.
      escape_analysis_ctx_->add_caller_callee(this->function_, called_function);
    }
  return TRAVERSE_CONTINUE;
}

// This class is used to traverse functions to build an imprecise
// topological ordering based on the call graph.

class Call_graph_traverse_functions : public Traverse
{
 public:
  Call_graph_traverse_functions(
      Escape_analysis* escape_analysis_ctx)
    : Traverse(traverse_functions),
      escape_analysis_ctx_(escape_analysis_ctx)
  { }

 protected:
  int
  function(Named_object*);

 private:
  // The escape analysis information.
  Escape_analysis* escape_analysis_ctx_;
};

// Explore the callees of a function.

int
Call_graph_traverse_functions::function(Named_object* no)
{
  this->escape_analysis_ctx_->add_function(no);

  go_assert(no->is_function());
  Function* func = no->func_value();

  Call_graph_traverse_expressions cgte(this->escape_analysis_ctx_, no);
  func->traverse(&cgte);

  return TRAVERSE_CONTINUE;
}

// This class is used to traverse the tree to look for uses of
// variables.

class Escape_analysis_traverse_expressions : public Traverse
{
 public:
  Escape_analysis_traverse_expressions(
      Escape_analysis_info* escape_analysis_info, Statement* statement)
    : Traverse(traverse_blocks | traverse_expressions),
      escape_analysis_info_(escape_analysis_info), statement_(statement)
  { }

 protected:
  // Only look at top-level expressions: do not descend into blocks.
  // They will be examined via Escape_analysis_traverse_statements.
  int
  block(Block*)
  { return TRAVERSE_SKIP_COMPONENTS; }

  int
  expression(Expression**);

 private:
  // The the escape analysis information.
  Escape_analysis_info* escape_analysis_info_;
  // The Statement in which we are looking.
  Statement* statement_;
};

// Is no a global variable?

static bool
is_global(const Named_object* no)
{
  return no->is_variable() && no->var_value()->is_global();
}

// Is no a parameter variable?

static bool
is_parameter(const Named_object* no)
{
  return no->is_variable() && no->var_value()->is_parameter();
}

// Is no a result variable?

static bool
is_result(const Named_object* no)
{
  return no->is_result_variable();
}

// Look for a reference to a variable in an expression.

int
Escape_analysis_traverse_expressions::expression(Expression** expr)
{
  (*expr)->get_escape_analysis_object(this->escape_analysis_info_);
  return TRAVERSE_CONTINUE;
}

// This class is used to handle an assignment statement.

class Escape_analysis_traverse_assignments : public Traverse_assignments
{
 public:
  Escape_analysis_traverse_assignments(
      Escape_analysis_info* escape_analysis_info, Statement* statement)
    : escape_analysis_info_(escape_analysis_info), statement_(statement)
  { }

 protected:
  void
  initialize_variable(Named_object*);

  void
  assignment(Expression** lhs, Expression** rhs);

  void
  value(Expression**, bool, bool)
  { }

 private:
  void
  do_assignment(Expression* lhs, Expression* rhs);

  // The escape analysis information.
  Escape_analysis_info* escape_analysis_info_;
  // The Statement in which we are looking.
  Statement* statement_;
};

// Handle a variable initialization.

void
Escape_analysis_traverse_assignments::initialize_variable(Named_object* var)
{
  // var = expr
  Expression* init = var->var_value()->init();
  if (init != NULL)
    {
      Escape_analysis_object* lhs =
	this->escape_analysis_info_->get_ea_object_for_variable(var, init);

      Escape_analysis_object* rhs =
	init->get_escape_analysis_object(this->escape_analysis_info_);

      this->escape_analysis_info_->variable_assignment_rule(lhs, rhs);
    }
}

// Handle an assignment in a statement.

void
Escape_analysis_traverse_assignments::assignment(Expression** plhs,
						 Expression** prhs)
{
  int field;
  Escape_analysis_object* inner_ref =
    (*plhs)->escape_analysis_split_base_index(this->escape_analysis_info_,
					      &field);

  Escape_analysis_object* rvalue =
    (*prhs)->get_escape_analysis_object(this->escape_analysis_info_);

  // Check whether this is a variable assignment or a field assigment.
  if (inner_ref != NULL)
    {
      if (rvalue != NULL)
	this->escape_analysis_info_->field_assignment_rule(inner_ref, field,
							   rvalue);
    }
  else
    {
      Escape_analysis_object* lvalue =
	(*plhs)->get_escape_analysis_object(this->escape_analysis_info_);

      // Not an assignement to some basic type.
      if (lvalue != NULL && (*plhs)->type()->has_pointer())
	  this->escape_analysis_info_->variable_assignment_rule(lvalue, rvalue);
    }
}

// This class is used to traverse the tree to look for statements.

class Escape_analysis_traverse_statements : public Traverse
{
 public:
  Escape_analysis_traverse_statements(
      Escape_analysis_info* escape_analysis_info)
    : Traverse(traverse_statements),
      escape_analysis_info_(escape_analysis_info)
  { }

 protected:
  int
  statement(Block*, size_t* pindex, Statement*);

 private:
  // The dataflow information.
  Escape_analysis_info* escape_analysis_info_;
};

// For each Statement, we look for expressions.

int
Escape_analysis_traverse_statements::statement(Block* block, size_t* pindex,
					       Statement *statement)
{
  // Traverse expressions first.
  // FIXME.  This is necessary because somehow
  // thunk statements are seen as assignments but their expression
  // are not traversed. See Thunk_statement::traverse_assignments.
  Escape_analysis_traverse_expressions eate(this->escape_analysis_info_,
					    statement);
  statement->traverse(block, pindex, &eate);

  // Next traverse assignments. This applies the analysis rules.
  Escape_analysis_traverse_assignments eata(this->escape_analysis_info_,
					    statement);
  statement->traverse_assignments(&eata);

  return TRAVERSE_CONTINUE;
}

// Fix a string to use as a filename. Used for filenames of debug dumps.

void
fix_string(std::string& s)
{
  for (unsigned int i = 0 ; i < s.length(); ++i)
    if ((s[i] < '0' || s[i] > 'z') && s[i] != '.')
      s[i]='_';
}

// Class Escape_analysis_info.

// Dump info to stream.

void
Escape_analysis_info::dump_to_stream(std::ostream& out)
{
  for (unsigned int i = 0; i < this->objects_.size(); i++)
    this->objects_[i]->dump_to_stream(out, false);
}

// Dump info to stream as dot.

void
Escape_analysis_info::dump_to_stream_as_dot(std::ostream& out)
{
  out << "digraph g {" << std::endl << "overlap=false;" << std::endl;
  for (unsigned int i = 0; i < this->objects_.size(); i++)
    this->objects_[i]->dump_to_stream_as_dot(out);
  out << "}" << std::endl;
}

// Destructor.

Escape_analysis_info::~Escape_analysis_info()
{
  // Dispose of analysis objects.
  for (EA_object_vector::iterator p = this->objects_.begin();
       p != this->objects_.end();
       ++p)
    delete *p;
}

// Add a phantom object node variable object. We allow the creation of only
// one phantom object per expression.

Escape_analysis_object*
Escape_analysis_info::add_phantom(Expression* expr,
				  Escape_analysis::Escape_level level
				    /* = Escape_analysis::NO_ESCAPE */,
				  Escape_analysis::Object_type obj_type
				    /* = Escape_analysis::PHANTOM */)
{
  Expression_map::iterator p = this->expr_object_map_.find(expr);
  if (p != this->expr_object_map_.end())
      // We have already seen this variable before.
    return p->second;
  Escape_analysis_object* phantom =
    this->make_object_for_expression(obj_type, expr, level);
  this->expr_object_map_[expr] = phantom;

  return phantom;
}

// Add a phantom object node variable object. We allow the creation of only
// one phantom object per named_object.

Escape_analysis_object*
Escape_analysis_info::add_phantom(const Named_object* no,
				  Escape_analysis::Escape_level level
				    /* = Escape_analysis::NO_ESCAPE */,
				  Escape_analysis::Object_type obj_type
				    /* = Escape_analysis::PHANTOM */)
{
  Named_object_map::iterator p = this->no_object_map_.find(no);
  if (p != this->no_object_map_.end())
    // We have already seen this variable before.
    return p->second;

  Escape_analysis_object* phantom =
    this->make_object_for_named_object(obj_type, no, level);
  this->no_object_map_[no] = phantom;

  return phantom;
}
// Get the escape analysis object representing a variable.

Escape_analysis_object*
Escape_analysis_info::get_ea_object_for_variable(const Named_object* no,
						 Expression* expr)
{
  Named_object_map::iterator p = this->named_object_references_map_.find(no);
  if (p != this->named_object_references_map_.end())
    // We have already seen this variable before.
    return p->second;

  Escape_analysis::Object_type object_type = Escape_analysis::REFVAR;
  Escape_analysis::Escape_level escape_level = Escape_analysis::NO_ESCAPE;

  if (::is_global(no))
    {
      object_type = Escape_analysis::GLOBAL;
    }
  else if (::is_result(no))
    {
      object_type = Escape_analysis::RETURN;
    }

  Escape_analysis_object* variable =
    this->make_object_for_named_object(object_type, no, escape_level);

  this->named_object_references_map_[no] = variable;

  // If we created a parameter variable, we will create a phantom node
  // This new node will be created on the first access though a parameter
  // variable. DO NOT MARK IT AS ARG_ESCAPE. Only its field pointers need
  // to be ARG_ESCAPE, and we will mark it on the propagation step.
  if (::is_parameter(no))
    {
      Escape_analysis_object* phantom_par =
	this->add_phantom(no, Escape_analysis::NO_ESCAPE,
			  Escape_analysis::OBJECT);
      variable->add_pointsto_edge(phantom_par);
      // Add a dummy points to field.
      Escape_analysis_object* parabstraction_ref =
	phantom_par->get_field_index_reference(-1);

      Escape_analysis_object* parabstraction =
	this->add_phantom(expr, Escape_analysis::ARG_ESCAPE,
			  Escape_analysis::PARAMETER);
      parabstraction_ref->add_pointsto_edge(parabstraction);


    }
  return variable;
}

// Get the escape analysis object associated with an expression.
// Each expression has at most one reference variable associated with it.
// TODO. Expression map can be replaced by a pointer in Expression for
// performance.

Escape_analysis_object*
Escape_analysis_info::get_ea_object_for_expression(Expression* expr)
{
  Expression_map::iterator p = this->expression_map_.find(expr);
  if (p != this->expression_map_.end())
    // We have already seen this expression before.
    return p->second;

  Escape_analysis_object* variable =
    this->make_object_for_expression(Escape_analysis::REFVAR, expr);
  this->expression_map_[expr] = variable;
  return variable;
}

// Get the escape analysis object associated with a temporary statement.
// Each temporary statement has at most one reference variable associated with
// it.
// TODO. Expression map can be replaced by a pointer in Temporary_statement for
// performance.

Escape_analysis_object*
Escape_analysis_info::get_ea_object_for_temporary_statement(
     const Temporary_statement* stm, Expression* expr)
{
  Temporary_object_map::iterator p = this->temporary_reference_map.find(stm);
  if (p != this->temporary_reference_map.end())
    // We have already seen this expression before.
    return p->second;

  Escape_analysis_object* ref =
    this->make_object_for_expression(Escape_analysis::REFVAR, expr);
  this->temporary_reference_map[stm] = ref;
  return ref;
}

// Process a constant literal of a basic type.
// FIXME. Ugly, every constant literal of a basic type is seen as
// as reference to its storage. Only need for implicit conversions
// to an empty interface type.
Escape_analysis_object*
Escape_analysis_info::process_constant(Expression* expr)
{
  return this->get_ea_object_for_expression(expr);
}

// Process a field reference (for reading).

Escape_analysis_object*
Escape_analysis_info::process_field_reference(Expression* outer,
					      Expression* inner,
					      int field_index)
{
  Escape_analysis_object* outer_ref = this->get_ea_object_for_expression(outer);
  Escape_analysis_object* inner_ref = inner->get_escape_analysis_object(this);

  // Treat as an assignment of the form outer = inner.field index.
  if (inner_ref != NULL)
    this->defer_to_field(outer_ref, inner_ref, field_index, outer);
  return outer_ref;
}

// Process an address of operation.
Escape_analysis_object*
Escape_analysis_info::process_address_of(Expression* outer, Expression* inner)
{
  Expression_map::iterator p = this->expression_map_.find(outer);
  if (p != this->expression_map_.end() && p->second != NULL)
      // We have already seen this expression before.
      return p->second;

  // Allocate the new object and add as points to to the reference variable.
  Escape_analysis_object* inner_ref = inner->get_escape_analysis_object(this);

  // NOTE. In some rare cases we might try to get the address of a constant
  // or an expression that evaluates to a value (via a temporary reference,
  // like in debug/proc/proc_linux.go doTrap()) so we create an object for
  // this case.
  if (inner_ref == NULL)
    inner_ref = this->get_ea_object_for_expression(inner);

  // Perform a field assignment outer.* = inner. Outer is of the form &var,
  // inner is of the form var.
  Escape_analysis_object* outer_ref = this->get_ea_object_for_expression(outer);
  Escape_analysis_object* outer_obj = this->add_phantom(outer);

  Escape_analysis_object* outer_fld = outer_obj->get_field_index_reference(-1);
  outer_ref->add_pointsto_edge(outer_obj);
  outer_fld->add_defer_edge(inner_ref);
  EA_object_set pointsto;
  inner_ref->compute_non_empty_pointsto_set(&pointsto);
  for (EA_object_set::iterator p = pointsto.begin(); p != pointsto.end(); p++)
    if (!(*p)->is_parameter())
      (*p)->set_object_type(Escape_analysis::OBJECT);

  return outer_ref;
}

// Implements the rule for x = y.
// Due to value semantics of go, assignment is always a value assignment.
// We will treat it as deferring fields to fields.

void
Escape_analysis_info::variable_assignment_rule(
    Escape_analysis_object* lvalue, Escape_analysis_object* rvalue)
{
  // If the type is a basic type, there is nothing to do.
  if (rvalue == NULL)
    return;

  // 1. Compute points to of rhs.
  EA_object_set rhs_pointsto;
  rvalue->compute_non_empty_pointsto_set(&rhs_pointsto);
  for (EA_object_set::iterator p = rhs_pointsto.begin();
       p != rhs_pointsto.end();
       ++p)
    {
      if ((*p)->edges_empty())
	(*p)->get_field_index_reference(-1);
      // 2. Make a reference from lhs.field to rhs.field
      for (EA_object_set::iterator field = (*p)->edges_begin();
	field != (*p)->edges_end();
	++field)
	{
	  // 3. Get the points to for the left hand side.
	  EA_object_set lhs_pointsto;
	  lvalue->compute_non_empty_pointsto_set(&lhs_pointsto);
	  for (EA_object_set::iterator q = lhs_pointsto.begin();
	      q != lhs_pointsto.end();
	      ++q)
	    {
	      Escape_analysis_object* lhs_field_ref =
		(*q)->get_field_index_reference((*field)->field_index());
	      lhs_field_ref->add_defer_edge((*field));
	    }
	}
    }
}

// Implements the rule for x.f = y.

void
Escape_analysis_info::field_assignment_rule(
    Escape_analysis_object* lvalue, int field_index,
    Escape_analysis_object* rvalue)
{

  // FIXME this is horribly expensive for methods that are very large.
  // It is not a problem in most of the library packages except for a
  // small set of functions such as in tls.serverHandshake.
  // An alternative would be to forget about keeping track of fields separately.
  // That would allow to take more advantage of defer edges and avoid some
  // of the pointsto computations.

  // For now we will abort the analysis if the number of objects exceeds a
  // threshold.

  // If the type is a basic type, there is nothing to do.
  if (rvalue == NULL)
    return;

  // 1. Compute points to of rhs.
  EA_object_set rhs_pointsto;
  rvalue->compute_pointsto_set(&rhs_pointsto);
  for (EA_object_set::iterator p = rhs_pointsto.begin();
       p != rhs_pointsto.end();
       ++p)
    {
      if ((*p)->edges_empty())
	(*p)->get_field_index_reference(-1);
      // 2. Make a reference from lhs.field to rhs.field
      for (EA_object_set::iterator field = (*p)->edges_begin();
	field != (*p)->edges_end();
	++field)
	{
	  // 3. Get the points to for the left hand side.
	  EA_object_set lhs_pointsto;
	  lvalue->compute_non_empty_pointsto_set(&lhs_pointsto);
	  for (EA_object_set::iterator q = lhs_pointsto.begin();
	      q != lhs_pointsto.end();
	      ++q)
	    {
	      Escape_analysis_object* lhs_field_ref =
		(*q)->get_field_index_reference(field_index);
	      EA_object_set lhs_field_pointsto;
	      lhs_field_ref->compute_non_empty_pointsto_set(
		  &lhs_field_pointsto);
	      for (EA_object_set::iterator r = lhs_field_pointsto.begin();
		   r != lhs_field_pointsto.end();
		   ++r)
		{
		  Escape_analysis_object* lhs_field_ref_ref =
		    (*r)->get_field_index_reference((*field)->field_index());
		  lhs_field_ref_ref->add_defer_edge((*field));
		}
	    }
	}
    }
}

// Process a construction. Arrays will be abstracted as having a single element
// reference (called with collapse_fields = true).
// Constructions are treated as assignments of the form left.field = val
// for each val.
// NOTE: Not called for construction maps or slices since they require
// to model the internal array that is allocated.
Escape_analysis_object*
Escape_analysis_info::process_construction(Expression* left,
					   Expression_list* vals,
					   bool collapse_fields)
{
  Escape_analysis_object* lvalue = this->get_ea_object_for_expression(left);

  if (vals != NULL)
    {
      int field_no = 0;
      for (Expression_list::iterator v = vals->begin();
	   v != vals->end();
	   ++v, ++field_no)
	if (*v != NULL)
	  {
	    Escape_analysis_object* val =
		  (*v)->get_escape_analysis_object(this);
	    int field_index = collapse_fields ? field_no : -1;
	    if (val != NULL)
	      this->field_assignment_rule(lvalue, field_index, val);
	  }
    }
  return lvalue;
}

// Process a slice or map construction. Slices and maps have an underlying
// array allocated that needs to be represented here.
// Container will be abstracted as having a single element reference.
// Constructions are treated as assignments of the form left.field = val
// for each val.
Escape_analysis_object*
Escape_analysis_info::process_container_construction(Expression* left,
						     Expression_list* vals)
{
  Escape_analysis_object* lvalue = this->get_ea_object_for_expression(left);

  // Now get hold of the internal array.
  EA_object_set pointsto;
  lvalue->compute_pointsto_set(&pointsto);
  Escape_analysis_object* array_ref;

  if (pointsto.empty())
    {
      // [lvalue] --> (slice_ref) --> [-1, array_ref] --> (inner_array_object)
      Escape_analysis_object* slice_ref = this->add_phantom(left);
      lvalue->add_pointsto_edge(slice_ref);
      array_ref = this->make_field_object(lvalue);
      array_ref->set_field_index(-1);
      slice_ref->add_field_edge(array_ref);
      Escape_analysis_object* inner_array_object =
	get_ea_object_for_allocation(left->location(), left);
      array_ref->add_pointsto_edge(inner_array_object);
    }
  else
    {
      go_assert(pointsto.size() == 1);
      Escape_analysis_object* slice_ref = *pointsto.begin();
      array_ref = slice_ref->get_field_index_reference(-1);
    }

  // Now process the values as if they where assignments to the an element
  // of the inner_array.
  if (vals != NULL)
    for (Expression_list::iterator v = vals->begin(); v != vals->end(); ++v)
      if (*v != NULL)
	{
	  Escape_analysis_object* val =
		(*v)->get_escape_analysis_object(this);
	  if (val != NULL)
	    this->field_assignment_rule(array_ref, -1, val);
	}

  return lvalue;
}

// Process a a conversion from a flat type to an interface, outer = (T)(inner)
// Behaves like an allocation and a variable assignment.
Escape_analysis_object*
Escape_analysis_info::process_convert_flat_to_interface(Expression* outer,
							Expression* inner)
{

  Escape_analysis_object* outer_ref = this->get_ea_object_for_expression(outer);
  Escape_analysis_object* inner_copy =
    this->get_ea_object_for_allocation(outer->location(), outer);

  outer_ref->add_pointsto_edge(inner_copy);

  Escape_analysis_object* inner_ref = inner->get_escape_analysis_object(this);
  this->variable_assignment_rule(outer_ref, inner_ref);
  return outer_ref;
}

// Process a receive through a channel.

Escape_analysis_object*
Escape_analysis_info::process_receive(Expression* receive_expr,
 				      Expression* channel)
{
  // A channel will be abstracted as a object with a single field.
  Escape_analysis_object* lvalue =
    this->get_ea_object_for_expression(receive_expr);
  Escape_analysis_object* val =
    channel->get_escape_analysis_object(this);

  this->defer_to_field(lvalue, val, -1, channel);

  return lvalue;
}

// Process a send through a channel.
void
Escape_analysis_info::process_send(Expression* channel,
 				      Expression* send_expr)
{
  // A channel will be abstracted as a object with a single field.
  Escape_analysis_object* rvalue =
    get_ea_object_for_expression(send_expr);
  Escape_analysis_object* chan =
    channel->get_escape_analysis_object(this);
  this->field_assignment_rule(chan, -1, rvalue);
}

// Access a call result from the tupled result.
Escape_analysis_object*
Escape_analysis_info::process_call_result(Expression* call_result,
					  Expression* inner, unsigned int index)
{
  Escape_analysis_object* lvalue =
    get_ea_object_for_expression(call_result);
  Escape_analysis_object* val =
    inner->get_escape_analysis_object(this);
  this->defer_to_field(lvalue, val, index, inner);
  return lvalue;
}

// Process an interface field reference.
Escape_analysis_object*
Escape_analysis_info::process_interface_field_reference(Expression* field_expr,
					  Expression*,  std::string&)
{
  // FIXME. Is this just to get the method reference? or are interfaces
  // treated as if they have data members. For the former nothing needs to be
  // done here and we could just return NULL.
  Escape_analysis_object* field =
    this->get_ea_object_for_expression(field_expr);
  field->set_escape_level(Escape_analysis::ARG_ESCAPE);

  return field;
}

// Process an assignment of the form left = right.field_index.

void
Escape_analysis_info::defer_to_field(Escape_analysis_object* left,
				     Escape_analysis_object* right,
				     int field_index,
				     Expression* right_indexed_exp)
{
  // Compute the points to set.
  EA_object_set pointsto;
  right->compute_non_empty_pointsto_set(&pointsto);

  // Traverse references to all field nodes on pointsto object with name equal
  // to field_index. If they don't exist, create one.
  // Add a deferred edge from left to each field node.
  for (EA_object_set::iterator p = pointsto.begin();
	p != pointsto.end();
	++p)
    {
      Escape_analysis_object* to = *p;
      // This is a points-to edge.
      go_assert(to->is_object());
      Escape_analysis_object* field =
	to->get_field_index_reference(field_index);

      left->add_defer_edge(field);

      // Force the creation of the referenced object at this point.
      // This is important because when we compute the pointsto set for the
      // new deferred reference, we don't want to create a phantom there.
      EA_object_set unused;
      field->compute_non_empty_pointsto_set(&unused, right_indexed_exp);
    }
}

// Process a call expression.

Escape_analysis_object*
Escape_analysis_info::process_call(const Named_object* const_no,
				   Call_expression* expr,
				   Expression_list* args,
				   bool is_void)
{
  Expression_list all_args;

  // FIXME. Here we include the receiver as an explicit argument.
  // Remove when this is done by the lowering pass.
  if (expr->fn()->bound_method_expression() != NULL)
    {
      // This is a method call, hence the receivers will be added as a
      // first parameter.
      // NOTE: this has to be in agreement with the escape information
      // when information about specific parameters is added.
      Bound_method_expression* bme = expr->fn()->bound_method_expression();
      all_args.push_back(bme->first_argument());
    }

  if (args != NULL)
    all_args.append(args);

  // This cast is safe, we already posses non const access to
  // all Named_objects that represent functions.
  Named_object* no = const_cast<Named_object*>(const_no);
  if (no != NULL && this->escape_analysis_->is_safe_function(no))
    return this->process_safe_call(expr, &all_args, is_void);
  else
    return this->process_unsafe_call(expr, &all_args, is_void);
}

// Compute the set of all reachable references.

static void
compute_reachable_references(EA_object_set* reachable_refs)
{
  std::queue<Escape_analysis_object*> open;
  EA_object_set closed;

  // Start with all nodes marked at escape_level
  for (EA_object_set::iterator p = reachable_refs->begin();
       p != reachable_refs->end();
       ++p )
    open.push(*p);

  while (!open.empty())
    {
      Escape_analysis_object* current = open.front();
      open.pop();
      closed.insert(current);

      if (current->is_reference())
	reachable_refs->insert(current);

      for (EA_object_set::iterator p = current->edges_begin();
	    p != current->edges_end();
	    ++p)
	{
	  Escape_analysis_object* obj = *p;
	  if (closed.count(obj) == 0)
	      open.push(obj);
	}
    }
}

// Process an unsafe call expression.

Escape_analysis_object*
Escape_analysis_info::process_unsafe_call(Expression* expr,
					  Expression_list* args, bool is_void)
{
  Escape_analysis_object* result_ref = this->get_ea_object_for_expression(expr);

  // FIXME.Mark every reference to a parameter as a global escape for now.
  if (args != NULL)
    {
      for (Expression_list::iterator p = args->begin(); p != args->end(); ++p)
	{
	  Escape_analysis_object* arg = (*p)->get_escape_analysis_object(this);
	  // Parameters are always passed by value, so only need to mark as
	  // global escape, all field for the objects arg points to.
	  if (arg != NULL)
	    {
	      EA_object_set pointsto;
	      arg->compute_non_empty_pointsto_set(&pointsto);
	      for (EA_object_set::iterator p = pointsto.begin();
		  p != pointsto.end();
		  ++p)
		// Iterate over edges.
		for (EA_object_set::iterator q = (*p)->edges_begin();
		    q != (*p)->edges_end();
		    ++q)
		  (*q)->set_escape_level( Escape_analysis::GLOBAL_ESCAPE);
	    }
	}
    }

  // void calls do not have an associated Escape_analysis object.
  if (is_void)
    return NULL;

  // FIXME. Call results are assumed to escape for now.
  result_ref->set_escape_level(Escape_analysis::GLOBAL_ESCAPE);

  return result_ref;
}

// Process a call to a safe function. A safe function does not leak its
// anything pointed by its parameters to a global but might leak into parameters
// and return values.
// A call to a safe function aliases all fields of objects pointed by parameters
// and call results together.

Escape_analysis_object*
Escape_analysis_info::process_safe_call(Expression* expr, Expression_list* args,
					bool is_void)
{
  // FIXME. A safe function aliases ALL reachable references. Another options is
  // to have the safety annotation associated with each parameter and that
  // would result in a more precise analysis.
  Escape_analysis_object* result_ref = this->get_ea_object_for_expression(expr);

  if (args != NULL)
    {
      for (Expression_list::iterator p = args->begin(); p != args->end(); ++p)
	{
	  Escape_analysis_object* arg = (*p)->get_escape_analysis_object(this);
	  // Parameters are always passed by value, so only need to mark as
	  // global escape, all field for the objects arg points to.
	  if (arg == NULL)
	    continue;

	  EA_object_set reachable_references;
	  reachable_references.insert(result_ref);
	  EA_object_set pointsto;
	  arg->compute_non_empty_pointsto_set(&pointsto);
	  for (EA_object_set::iterator p = pointsto.begin();
	      p != pointsto.end();
	      ++p)
	    // Iterate over edges.
	    for (EA_object_set::iterator q = (*p)->edges_begin();
		q != (*p)->edges_end();
		++q)
	      // Compute initial reachable references.
	      reachable_references.insert(*q);

	  compute_reachable_references(&reachable_references);
	  for (EA_object_set::iterator reach_ref = reachable_references.begin();
	       reach_ref != reachable_references.end();
	       ++reach_ref)
	  {
	    // Alias every field in the points to of the actuals to
	    // the dummy node for the expression.
	    (*reach_ref)->add_defer_edge(result_ref);
	    result_ref->add_defer_edge(*reach_ref);
	  }
	}
    }

  // void calls do not have an associated return object.
  if (is_void)
    return NULL;

  return result_ref;
}

// Process an unsafe type cast.

Escape_analysis_object*
Escape_analysis_info::process_unsafe_conversion(Expression* expr)
{
  Escape_analysis_object* obj = expr->get_escape_analysis_object(this);
  obj->set_escape_level(Escape_analysis::GLOBAL_ESCAPE);
  return obj;
}

// Process slice creation.

Escape_analysis_object*
Escape_analysis_info::process_slice_creation(Expression* slice_creation,
					     Expression* array)
{
  Escape_analysis_object* slice_ref =
    this->get_ea_object_for_expression(slice_creation);

  Escape_analysis_object* array_ref =
    array->get_escape_analysis_object(this);

  EA_object_set pointsto;
  slice_ref->compute_non_empty_pointsto_set(&pointsto);
  for (EA_object_set::iterator p = pointsto.begin();
      p != pointsto.end();
      ++p)
    {
      EA_object_set array;
      array_ref->compute_non_empty_pointsto_set(&array);
      for (EA_object_set::iterator q = array.begin();
	   q != array.end();
	   ++q)
	if (!(*q)->is_parameter())
	  (*q)->set_object_type(Escape_analysis::OBJECT);

      Escape_analysis_object* field_ref = (*p)->get_field_index_reference(-1);
      field_ref->add_defer_edge(array_ref);
    }

  return slice_ref;
}

// Process slice element access.
Escape_analysis_object*
Escape_analysis_info::process_slice_access(Expression* slice_access,
					   Expression* slice)
{
  Escape_analysis_object* slice_access_ref =
    this->get_ea_object_for_expression(slice_access);

  Escape_analysis_object* slice_ref =
    slice->get_escape_analysis_object(this);

  // Compute points to
  EA_object_set pointsto;
  slice_ref->compute_non_empty_pointsto_set(&pointsto);
  for (EA_object_set::iterator p = pointsto.begin();
      p != pointsto.end();
      ++p)
    {
      // *p represents actual storage the pointer to the underlying array.
      // Make this an alias for the element field of the underlying array.

      Escape_analysis_object* array_ref =
	(*p)->get_field_index_reference(-1);

      // Compute all concrete arrays this might point to.
      EA_object_set arrays;
      array_ref->compute_non_empty_pointsto_set(&arrays, slice_access);
      for (EA_object_set::iterator q = arrays.begin();
	    q != arrays.end();
	    ++q)
	{
	  // Alias the field reference.
	  Escape_analysis_object* element_ref =
	    (*q)->get_field_index_reference(-1);
	  element_ref->add_defer_edge(slice_access_ref);
	  slice_access_ref->add_defer_edge((element_ref));
	}
    }

  return slice_access_ref;
}

// Process an escaping thunk expression.

void
Escape_analysis_info::process_go_statement(Expression*, Expression_list* args)
{
  // Mark every reference to a parameter as a global escape, there is
  // no need to propagate.
  if (args != NULL)
    {
      for (Expression_list::iterator p = args->begin(); p != args->end(); ++p)
	{
	  Escape_analysis_object* arg = (*p)->get_escape_analysis_object(this);
	  // Parameters are always passed by value, so only need to mark as
	  // global escape, all field for the objects arg points to.
	  if (arg != NULL)
	    {
	      EA_object_set pointsto;
	      arg->compute_pointsto_set(&pointsto);
	      for (EA_object_set::iterator p = pointsto.begin();
		  p != pointsto.end();
		  ++p)
		// iterate over edges
		for (EA_object_set::iterator q = (*p)->edges_begin();
		    q != (*p)->edges_end();
		    ++q)
		  (*q)->set_escape_level(Escape_analysis::GLOBAL_ESCAPE);
	    }
	}
    }
}

// Process a function reference.

Escape_analysis_object*
Escape_analysis_info::process_function_reference(Expression* fn,
					      Expression* closure)
{
  Expression_map::iterator p = this->expression_map_.find(fn);
  if (p != this->expression_map_.end() && p->second != NULL)
      // We have already seen this expression before.
      return p->second;

  Escape_analysis_object* func_ref = this->get_ea_object_for_expression(fn);
  if (closure != NULL)
    {
      Escape_analysis_object* closure_ref =
	closure->get_escape_analysis_object(this);
      // FIXME. Mark closure as escaping globally for now. It should only be
      // marked as globally escaping if the nested function is not safe.
      closure_ref->set_escape_level(Escape_analysis::GLOBAL_ESCAPE);
      func_ref->add_defer_edge(closure_ref);
    }

  return func_ref;
}

// Add an allocation site to a location possibly related to an expression.

Escape_analysis_object*
Escape_analysis_info::get_ea_object_for_allocation(source_location loc,
						   Expression* expr)
{
  Location_object_map::iterator p = this->location_object_map_.find(loc);
  if (p != this->location_object_map_.end())
    // We have already seen this variable before.
    return p->second;

  Escape_analysis_object* obj =
    this->make_object_for_expression(Escape_analysis::OBJECT, expr);
  this->location_object_map_[loc] = obj;

  return obj;
}

// Add a reference to an allocation.

Escape_analysis_object*
Escape_analysis_info::process_allocation(Expression* expr, source_location loc)
{
  Escape_analysis_object* allocation =
    this->get_ea_object_for_allocation(loc, expr);
  Escape_analysis_object* allocation_addr = this->add_phantom(expr);
  Escape_analysis_object* reference_addr_ref =
    this->get_ea_object_for_expression(expr);
  reference_addr_ref->add_pointsto_edge(allocation_addr);
  Escape_analysis_object* allocation_deref =
    allocation_addr->get_field_index_reference(-1);
  allocation_deref->add_pointsto_edge(allocation);

  return reference_addr_ref;
}

// Make a new analysis object associated to a named object.

Escape_analysis_object*
Escape_analysis_info::make_object_for_named_object(
    Escape_analysis::Object_type obj_type,
    const Named_object* named_object,
    Escape_analysis::Escape_level level /* = NO_ESCAPE */)
{
  return this->make_object(obj_type, named_object, NULL, level);
}

// Make a new analysis object associated to an expression.

Escape_analysis_object*
Escape_analysis_info::make_object_for_expression(
    Escape_analysis::Object_type obj_type,
    Expression* expr,
    Escape_analysis::Escape_level level /* = NO_ESCAPE */)
{
  return this->make_object(obj_type, NULL, expr, level);
}

// Make a new analysis object for a field.

Escape_analysis_object*
Escape_analysis_info::make_field_object(Escape_analysis_object* parent)
{
  // FIXME. For now use the same expression/object as the parent.
  // This is used to create phantom objects later.
  return this->make_object(Escape_analysis::FIELD, parent->object(),
			   parent->expression(), Escape_analysis::NO_ESCAPE);
}

// Threshold for where not to use this analysis.
static const unsigned int MAX_OBJECTS_THRESHOLD = 300;

// Make a new analysis object.

Escape_analysis_object*
Escape_analysis_info::make_object(Escape_analysis::Object_type obj_type,
				  const Named_object* no, Expression* expr,
				  Escape_analysis::Escape_level level)
{
  Escape_analysis_object* newobj =
    new Escape_analysis_object(obj_type, this->objects_.size(),this, no,
			       expr, level);
  this->objects_.push_back(newobj);
  this->updated_ = true;
  // Use a threshold to abort the analysis if deemed to expensive.
  if (this->objects_.size() > MAX_OBJECTS_THRESHOLD)
    this->abort_analysis();
  return newobj;
}

// Propagate the escape level though the graph.

void
Escape_analysis_info::propagate_escape_level()
{
  // Populate field with empty points to unroll parameters enough that
  // we can detect leaks.
  for (unsigned int i = 0; i < this->objects_.size(); i++)
    if (this->objects_[i]->is_reference())
      {
	EA_object_set unused;
	this->objects_[i]->compute_non_empty_pointsto_set(&unused);
      }

  // Mark objects pointed by results field as ARG_ESCAPE and
  // globals as GLOBAL_ESCAPE. Parameters are marked on creation.
  for (unsigned int i = 0; i < this->objects_.size(); i++)
    {
      Escape_analysis_object* obj = this->objects_[i];
      if (obj->is_global() || obj->is_result())
	{
	  EA_object_set pointsto;
	  obj->compute_pointsto_set(&pointsto);
	  for (EA_object_set::iterator p = pointsto.begin();
	       p != pointsto.end();
	       ++p)
	    for (EA_object_set::iterator q = (*p)->edges_begin();
		 q != (*p)->edges_end();
		 ++q)
	      {
		EA_object_set fields_pointsto;
		(*q)->compute_pointsto_set(&fields_pointsto);
		for (EA_object_set::iterator r = fields_pointsto.begin();
		     r != fields_pointsto.end();
		     ++r)
		  (*r)->set_escape_level(obj->is_global()
					 ? Escape_analysis::GLOBAL_ESCAPE
					 : Escape_analysis::ARG_ESCAPE );
	      }
	}
    }

  // Propagate GLOBAL_ESCAPE.
  this->propagate_escape_level(Escape_analysis::GLOBAL_ESCAPE);
  // Propagate ARG_ESCAPE.
  this->propagate_escape_level(Escape_analysis::ARG_ESCAPE);
}

// Propagate an escape level though the graph, assuming all greater levels have
// already been propagated.

void
Escape_analysis_info::propagate_escape_level(
    Escape_analysis::Escape_level escape_level)
{
  std::queue<Escape_analysis_object*> open;
  EA_object_set closed;

  // Start with all nodes marked at escape_level
  for (EA_object_vector::iterator p = this->objects_.begin();
       p != this->objects_.end();
       ++p )
    if ((*p)->escape_level() == escape_level)
      open.push(*p);

  while (!open.empty())
    {
      Escape_analysis_object* current = open.front();
      open.pop();
      closed.insert(current);

      if (current->escape_level() <= escape_level)
	current->set_escape_level(escape_level);

      for (Escape_analysis_object::iterator p = current->edges_begin();
	    p != current->edges_end();
	    ++p)
	{
	  Escape_analysis_object* obj = *p;
	    if (closed.count(obj) == 0)
	      open.push(obj);
	}
    }
}

// Check if the function is safe by traversing the graph.
// Note that this could be done while propagating the escape level, but
// this way is easier to read and consider that only a small part of the graph
// is reachable from the parameters.

bool
Escape_analysis_info::is_safe_function()
{
  // Check whether a global escaping node is reachable from parameters or
  // returns.
  std::queue<Escape_analysis_object*> open;
  EA_object_set closed;

  // Start will all nodes pointed by parameters or returns.
  for (EA_object_vector::iterator p = this->objects_.begin();
       p != this->objects_.end();
       ++p )
    if (((*p)->is_parameter() || (*p)->is_result()) && (*p)->has_pointer())
      open.push(*p);

  while (!open.empty())
    {
      Escape_analysis_object* current = open.front();
      open.pop();
      closed.insert(current);

      if (current->escape_level() == Escape_analysis::GLOBAL_ESCAPE)
	return false;

      for (Escape_analysis_object::iterator p = current->edges_begin();
	   p != current->edges_end();
	   ++p)
	{
	  Escape_analysis_object* obj = *p;
	  if (closed.count(obj) == 0)
	    open.push(obj);
	}
    }
    return true;
}

// Report results as error.

void
Escape_analysis_info::report_as_errors()
{
  for (EA_object_vector::iterator p = objects_.begin();
       p != objects_.end();
       ++p)
    (*p)->report_as_error();
}

// Propagate the analysis results to the ast nodes.

void
Escape_analysis_info::propagate_analysis_results()
{
  // Iterate over objects
  for (EA_object_vector::iterator p = this->objects_.begin();
       p != this->objects_.end();
       ++p)
    {
      Escape_analysis_object* obj = (*p);
      if (obj->object_type() == Escape_analysis::OBJECT
	  && obj->escape_level() == Escape_analysis::NO_ESCAPE)
	{
	  if (obj->expression() != NULL)
	    {
	      Expression* expr = obj->expression();
	      expr->unset_escapes_function();
	    }
	  else if (obj->object() != NULL && obj->object()->is_variable())
	    {
	      Variable* var = const_cast<Variable*>(obj->object()->var_value());
	      var->unset_escapes_function();
	    }
	}
    }
}

// class Escape_analysis_object

// Constructor.
Escape_analysis_object::Escape_analysis_object(
    Escape_analysis::Object_type object_type,
    unsigned int id,
    Escape_analysis_info* escape_info,
    const Named_object* no,
    Expression* expr,
    Escape_analysis::Escape_level escape_level)
  : object_type_(object_type), escape_level_(escape_level), object_id_(id),
    object_(no), expression_(expr), field_index_(0), escape_info_(escape_info)
{
}

static void
escape_string(std::string from, std::string& s)
{
  s.reserve(from.length() * 4 + 2);
  for (std::string::const_iterator p = from.begin();
       p != from.end();
       ++p)
    {
      if (*p == '\\' || *p == '"')
	{
	  s += '\\';
	  s += *p;
	}
      else if (*p >= 0x20 && *p < 0x7f)
	s += *p;
      else if (*p == '\n')
	s += "\\n";
      else if (*p == '\t')
	s += "\\t";
      else
	{
	  s += "\\x";
	  unsigned char c = *p;
	  unsigned int dig = c >> 4;
	  s += dig < 10 ? '0' + dig : 'A' + dig - 10;
	  dig = c & 0xf;
	  s += dig < 10 ? '0' + dig : 'A' + dig - 10;
	}
    }
}

// Sets the escape level of this object.

void
Escape_analysis_object::set_escape_level(Escape_analysis::Escape_level lvl)
{
  if (this->escape_level_ != lvl)
    this->escape_info_->set_updated();
  this->escape_level_ = lvl;
}

// Sets the object type of this object.

void
Escape_analysis_object::set_object_type(Escape_analysis::Object_type type)
{
  if (this->object_type_ != type)
    this->escape_info_->set_updated();
  this->object_type_ = type;
}

// Does the object have a pointer type?

bool Escape_analysis_object::has_pointer()
{
  if (this->expression_ != NULL)
    return this->expression_->type()->has_pointer();
  else if (this->object_!= NULL && this->object_->is_variable())
    return this->object_->var_value()->type()->has_pointer();
  else if (this->object_!= NULL && this->object_->is_result_variable())
    return this->object_->result_var_value()->type()->has_pointer();
  return true;
}

// Add a deferred edge to the connection graph.

void
Escape_analysis_object::add_defer_edge(Escape_analysis_object* object)
{
  // this --- d ---> object
  go_assert(this->is_reference() && object->is_reference());
  std::pair<EA_object_set::iterator,bool> ret;
  ret = this->out_edges_.insert(object);
  if (ret.second)
    this->escape_info_->set_updated();
}

// Add a field edge to the connection graph.
void
Escape_analysis_object::add_field_edge(Escape_analysis_object* object)
{
  // this --- f ---> object
  go_assert(this->is_object() && object->is_field());

  std::pair<std::set<Escape_analysis_object*>::iterator,bool> ret;
  ret = this->out_edges_.insert(object);
  if (ret.second)
    this->escape_info_->set_updated();
}

// Add a points-to edge to the connection graph.

void
Escape_analysis_object::add_pointsto_edge(Escape_analysis_object* object)
{
  // this --- p ---> object
  go_assert(this->is_reference() && object->is_object());

  std::pair<std::set<Escape_analysis_object*>::iterator,bool> ret;
  ret = this->out_edges_.insert(object);
  if (ret.second)
    this->escape_info_->set_updated();
}

// Dump an object representation to a stream for debugging.

void
Escape_analysis_object::dump_to_stream(std::ostream& out,
				       bool just_result /* = true */)
{
  if (just_result && this->object_type_ != Escape_analysis::OBJECT)
    return;

  out << this->object_id_ << " " ;
  switch (this->object_type_)
    {
    case Escape_analysis::REFVAR:
      out << "REFVAR ";
      break;
    case Escape_analysis::GLOBAL:
      out << "GLOBAL ";
      break;
    case Escape_analysis::RETURN:
      out << "RETURN ";
      break;
    case Escape_analysis::OBJECT:
      out << "ALLOCATION ";
      break;
    case Escape_analysis::PARAMETER:
      out << "PARAMETER ";
      break;
    case Escape_analysis::PHANTOM:
      out << "PHANTOM ";
      break;
    case Escape_analysis::FIELD:
      out << "FIELD " << this->field_index_ << " ";
      break;
    default:
      out << "UNKNOWN ";
      break;
    }

  out << this->escape_level_ << " " ;

  std::stringstream strout;
  std::string s;

  if (this->object_ != NULL)
    strout << this->object_->name();
  else if (this->expression_ != NULL)
    Ast_dump_context::dump_to_stream(this->expression_, &strout);

  escape_string(strout.str(), s);
  out << s;

  if (!just_result)
    for (std::set<Escape_analysis_object*>::iterator p = out_edges_.begin();
	p != out_edges_.end();
	++p)
      {
	Escape_analysis_object* to = *p;
	out << std::endl << "   ---->  " << to->object_id();
      }

  out << std::endl;
}

void
Escape_analysis_object::dump_to_stream_as_dot(std::ostream& out)
{
  out << this->object_id_ << " ["
      << (this->is_reference() ? "shape=box " : "" );

  if (this->escape_level_ == Escape_analysis::GLOBAL_ESCAPE)
    out << " style=filled color=lightsalmon ";
  else if (this->escape_level_ == Escape_analysis::ARG_ESCAPE)
    out << " style=filled color=lightblue ";
  out << " label=\"" << this->object_id_ << " ";
  switch (this->object_type_)
    {
    case Escape_analysis::REFVAR:
      out << "REFVAR ";
      break;
    case Escape_analysis::GLOBAL:
      out << "GLOBAL ";
      break;
    case Escape_analysis::RETURN:
      out << "RETURN ";
      break;
    case Escape_analysis::OBJECT:
      out << "ALLOCATION ";
      break;
    case Escape_analysis::PARAMETER:
      out << "PARAMETER ";
      break;
    case Escape_analysis::PHANTOM:
      out << "PHANTOM ";
      break;
    case Escape_analysis::FIELD:
      out << "FIELD " << this->field_index_ << " ";
      break;
    default:
      out << "UNKNOWN ";
      break;
    }

  std::stringstream strout;
  std::string s;

  if (this->object_ != NULL)
      strout << this->object_->name()
	     << " L(" << LOCATION_LINE(this->object_->location()) << ")";
  else if (this->expression_ != NULL)
    {
      Ast_dump_context::dump_to_stream(this->expression_, &strout);
      strout << " L(" << LOCATION_LINE(this->expression_->location()) << ")";
    }
  else if (!this->is_field())
    strout << "unknown";

  escape_string(strout.str(), s);
  out << s << "\"];" << std::endl;
  for (std::set<Escape_analysis_object*>::iterator p = out_edges_.begin();
       p!= out_edges_.end();
       ++p)
    {
      Escape_analysis_object* to = *p;
      const char* style = "";
      if (this->is_reference() && to->is_reference())
	style = " [style=dotted]";
      out << this->object_id_ << " ->  " << to->object_id()
	  << style << ";" << std::endl;
    }
}

// Compute the directly points to set.

void
Escape_analysis_object::compute_pointsto_set(EA_object_set* pointsto)
{
  // We compute the closure of deferred edges.
  go_assert(this->is_reference());
  std::queue<Escape_analysis_object*> open;
  std::set<Escape_analysis_object*> closed;
  // Objects pending to explore.
  open.push(this);

  while (!open.empty())
    {
      if (this->escape_info_->aborted())
	return;
      Escape_analysis_object* next = open.front();
      open.pop();
      go_assert(next->is_reference());
      closed.insert(next);
      for (Escape_analysis_object::iterator p = next->edges_begin();
	   p != next->edges_end();
	   ++p)
	{
	  if (closed.count(*p) == 0)
	    {
	      if ((*p)->is_reference())
		open.push(*p);
	      else // *p is an object.
		pointsto->insert(*p);
	    }
	}
    }
}

// Get the reference node representing the field access.

Escape_analysis_object*
Escape_analysis_object::get_field_index_reference(int field_index)
{
  go_assert(this->is_object());
  for (Escape_analysis_object::iterator p = this->out_edges_.begin();
       p != this->out_edges_.end();
       ++p)
    {	// -1 represents all contents. Fields collapse to -1 when an object is
	// accessed though an interface.
        if ((*p)->object_type_ == Escape_analysis::FIELD
	    && ((*p)->field_index_ == field_index || (*p)->field_index_ == -1))
	return *p;
    }

  Escape_analysis_object* field =
    this->escape_info_->make_field_object(this);
  field->set_field_index(field_index);
  // Field references are collapsed once the field index -1 is created.
  if (field_index == -1)
    for (Escape_analysis_object::iterator p = this->out_edges_.begin();
	p != this->out_edges_.end();
	++p)
	  if ((*p)->object_type_ == Escape_analysis::FIELD )
	    {
	      (*p)->add_defer_edge(field);
	      field->add_defer_edge(*p);
	    }

  this->add_field_edge(field);

  return field;
}

// Compute that the pointsto set that is non empty by creating a phantom node if
// needed. If expr is provided the phantom node will be associated with it.

void
Escape_analysis_object::compute_non_empty_pointsto_set(EA_object_set* pointsto,
						       Expression* expr
						      /* = NULL */)
{
  this->compute_pointsto_set(pointsto);
  if (pointsto->empty())
    {
      // FIXME. If no expression is given, used the same as in the
      // reference (this object).
      if (expr == NULL && this->expression_ != NULL)
	expr = this->expression_;

      Escape_analysis_object* phantom;

      if (expr != NULL)
	phantom = this->escape_info_->add_phantom(expr);
      else
	phantom = this->escape_info_->add_phantom(this->object_);
      this->add_pointsto_edge(phantom);
      pointsto->insert(phantom);
    }
}

// Report escape decisions as errors.

bool
Escape_analysis_object::report_as_error()
{
  if (this->object_ != NULL && this->is_object())
    {
      // the default for variables is to not escape.
      if (this->escape_level_ == Escape_analysis::GLOBAL_ESCAPE)
	 error_at(this->object_->location(), "%ld %s %s",
		  this->object_id_,
		  this->object_->name().c_str(),
		  _("escapes globally (move to heap)"));
      else if (this->escape_level_ == Escape_analysis::ARG_ESCAPE)
	 error_at(this->object_->location(), "%ld %s %s",
		  this->object_id_,
		  this->object_->name().c_str(),
		  _("escapes through parameter (move to heap)"));

    }
  else if (this->expression_ != NULL && this->is_object())
    {
      std::stringstream s;
      Ast_dump_context::dump_to_stream(this->expression_, &s);
      if (this->object_type_ == Escape_analysis::OBJECT
	  && this->escape_level_ == Escape_analysis::NO_ESCAPE)
	 error_at(this->expression_->location(), "%ld %s %s",
		  this->object_id_,
		  s.str().c_str(),
		  _("is captured (move to stack)"));
      else if (this->object_type_ == Escape_analysis::OBJECT
	       && this->escape_level_ == Escape_analysis::ARG_ESCAPE)
	error_at(this->expression_->location(), "%ld %s %s",
		 this->object_id_,
		  s.str().c_str(),
		  _("escapes through parameter (move to heap)"));
      else if (this->object_type_ == Escape_analysis::OBJECT
	       && this->escape_level_ == Escape_analysis::GLOBAL_ESCAPE)
	error_at(this->expression_->location(), "%ld %s %s",
		  this->object_id_,
		 s.str().c_str(),
		  _("escapes globally (move to heap)"));
    }
  return false;
}

// Class Escape_analysis.

// Destructor
Escape_analysis::~Escape_analysis()
{
  for (Escape_info_map::iterator p = this->escape_info_map_.begin();
       p != this->escape_info_map_.end();
       ++p)
    {
      delete p->second;
    }
}

// Initialize the escape information for each function.

Escape_analysis_info*
Escape_analysis::initialize_escape_info(Named_object* no)
{
  Escape_analysis_info* escape_info = new Escape_analysis_info(this);

  this->escape_info_map_[no] = escape_info;

  return escape_info;
}

// Compute the list of functions to analyse and determine
// a good ordering based on the topological sorting of an approximate
// call graph.

void
Escape_analysis::compute_functions_to_process(Gogo* gogo)
{
  // Compute the approximate call graph.
  Call_graph_traverse_functions cgtf(this);
  gogo->traverse(&cgtf);

  // Do a (quasi) topological sort. The graph might be cyclic.
  std::queue<Named_object*> current;

  // Compute the functions that have no callers.
  for (Named_object_set::iterator p = this->functions_.begin();
       p != this->functions_.end();
       ++p)
    if (this->caller_map[*p].empty())
      current.push(*p);

  while (!current.empty())
    {
      Named_object* caller = current.front();
      current.pop();
      this->sorted_functions_.push_back(caller);
      // Remove incoming edges from callees and if empty add to current.
      for (Caller_map::iterator p = this->caller_map.begin();
	   p != this->caller_map.end();
	   ++p)
	{
	  if (p->second.count(caller) != 0)
	    {
	      p->second.erase(caller);
	      if (p->second.empty())
		{
		  // FIXME. Cast of non const to const because it is only used
		  // if we already have a non const reference in functions.
		  Named_object* callee = const_cast<Named_object*>(p->first);
		  if (this->functions_.count(callee) != 0)
		    current.push(callee);
		}
	    }
	}
    }

  // All the functions in the caller map with a non empty,
  // callers set are involved in a cycle, just add those
  // in any order
  for (Caller_map::iterator p = this->caller_map.begin();
	p != this->caller_map.end();
	++p)
    {
      Named_object* callee = const_cast<Named_object*>(p->first);
      if (!p->second.empty()
	  && this->functions_.count(callee) != 0)
	this->sorted_functions_.push_back(callee);
    }
}

 // Perform the analysis in the prescribed function order.

void
Escape_analysis::compute_analysis_results()
{
  for (Named_object_vector::reverse_iterator p =
	 this->sorted_functions_.rbegin();
       p != this->sorted_functions_.rend();
       ++p)
    {
      Named_object* no = *p;
      go_assert(no->is_function());
      Function* func = no->func_value();

      Escape_analysis_info* escape_analysis_info =
	this->initialize_escape_info(no);
      // Perform the analysis for a single function.
      do
	{
	  escape_analysis_info->set_updated(false);
	  Escape_analysis_traverse_statements eats(escape_analysis_info);
	  func->traverse(&eats);
	}
      while (escape_analysis_info->updated()
	     && !escape_analysis_info->aborted());

      if (!escape_analysis_info->aborted())
	{
	  // Propagate the escape level through the graph.
	  escape_analysis_info->propagate_escape_level();

	  // Finally mark as safe if it is.
	  if (escape_analysis_info->is_safe_function())
	    this->safe_functions_.insert(no);
	}
    }
}

// Do the escape analysis and annotate allocations.

void Escape_analysis::perform(Gogo* gogo)
{
  // Initialize escape information.
  Escape_analysis escape_analysis;

  // Compute a reasonable order to analyze functions so that a fixpoint
  // computation is avoided here. NOTE: There is a fixpoint computation
  // when computing the connection graph of each function. To improve
  // precision in the case of recursive functions, a fixpoint is
  // is needed at this level.
  escape_analysis.compute_functions_to_process(gogo);

  // Perform the analysis in the prescribed order.
  escape_analysis.compute_analysis_results();

  // After the whole analysis is done we will
  // report information about all variables and
  // allocations as error to check with errchk.
  // We should have an appropriate flag for that.
  if (generate_error_from_escape.is_enabled())
    for (Escape_info_map::iterator p = escape_analysis.escape_info_map_.begin();
	 p != escape_analysis.escape_info_map_.end();
	 ++p)
      {
	if (p->second->aborted())
	  {
	    error_at(p->first->location(), "%s %s", p->first->name().c_str(),
		    _("analysis aborted"));
	    continue;
	  }

	if (escape_analysis.safe_functions_.count(p->first) != 0)
	  error_at(p->first->location(), "%s %s", p->first->name().c_str(),
		    _("is safe"));
	p->second->report_as_errors();
      }

  // Dump the connection graph for each function if the -fgo-dump-esc is
  // enabled
  if (dump_escape_as_dot.is_enabled())
    for (Escape_info_map::iterator p = escape_analysis.escape_info_map_.begin();
	 p != escape_analysis.escape_info_map_.end();
	 ++p)
      {
	// Dump in dot format to one file per function.
	// FIXME. Methods attached to different types might
	// have the same name in which case the file is overwritten.
	std::ofstream fout;
	std::string name("dot-dump");
	name +=  p->first->name();
	name += ".dot";
	fix_string(name);
	fout.open(name.c_str());
	if (!fout.fail())
	  {
	    p->second->dump_to_stream_as_dot(fout);
	    fout.close();
	  }
      }

  // Propagate the analysis results to the corresponding ast objects.
  for (Escape_info_map::iterator p = escape_analysis.escape_info_map_.begin();
       p != escape_analysis.escape_info_map_.end();
	++p)
    p->second->propagate_analysis_results();
}

// Perform stack allocation optimization.

void Gogo::optimize_allocation()
{
  if (::stack_alloc_optimization_flag.is_enabled())
    {
      Escape_analysis::perform(this);
    }
}