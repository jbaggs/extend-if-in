##! Extended if_in criteria to generate notices on, beyond the initial if_in restrictions.
module Intel;

# Extended if_in criteria organized by meta.source, then indicator_type.
redef extended_if_in = {
	["doh.servers"] = table([Intel::DOMAIN]=set(DNS::IN_REQUEST)),
};


