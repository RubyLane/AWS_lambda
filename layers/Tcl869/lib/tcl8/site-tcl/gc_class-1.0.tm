oo::class create ::gc_class {
	superclass ::oo::class

	method instvar {varname args} {
		upvar 1 $varname scopevar
		if {[array exists scopevar]} {
			error "Can't use $varname for the instance variable: it exists and is an array"
		}
		# Chain to [new] using an uplevel to preserve the relative callframe context vs [new] and [create]
		set scopevar [uplevel 1 [list [namespace origin my] new {*}$args]]
		set fqobj [namespace origin $scopevar]
		trace add variable scopevar {write unset} [list [namespace origin my] _gc $fqobj]
		return ""
	}

	method _gc {fqobj name1 name2 op} {
		upvar 1 $name1 scopevar
		if {[info object isa object $fqobj]} { $fqobj destroy }
		trace remove variable scopevar {write unset} [list [namespace origin my] _gc $fqobj]
	}

	#unexport create new
}

# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
