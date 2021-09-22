##! This script generates notices on extended "if_in" criteria.
##! Indicators must have a meta.if_in restriction defined for these extensions to have effect.

@load policy/frameworks/intel/do_notice

module Intel;

# Extended if_in criteria organized by meta.source, then indicator_type:
const extended_if_in: table[string] of table[Intel::Type] of set[Intel::Where] &redef;

event Intel::match(s: Seen, items: set[Item])
	{
	for ( item in items )
		{
		if ( item$meta$do_notice && item$meta?$if_in && s$where != item$meta$if_in && 
			item$meta$source in extended_if_in &&
			item$indicator_type in extended_if_in[item$meta$source] && 
			s$where in extended_if_in[item$meta$source][item$indicator_type] )
			{
			Reporter::info(fmt("Intel where: %s", s$where));
			local n = Notice::Info($note=Intel::Notice,
				$msg = fmt("Intel hit on %s at %s", s$indicator, s$where),
				$sub = s$indicator);
			local service_str = "";

			if ( s?$conn )
				{
				n$conn = s$conn;

				# Add identifier composed of indicator, originator's and responder's IP,
				# and where seen, without considering the direction of the flow.
				local intel_id = s$indicator;
				if( s$conn?$id )
					{
					if( s$conn$id$orig_h < s$conn$id$resp_h)
						intel_id = cat(intel_id, s$conn$id$orig_h, s$conn$id$resp_h, s$where);
					else
						intel_id = cat(intel_id, s$conn$id$resp_h, s$conn$id$orig_h, s$where);
					}
				n$identifier = intel_id;

				if ( s$conn?$service )
					{
					for ( service in s$conn$service )
						service_str = cat(service_str, service, " ");
					}
				}

			# Add additional information to the generated mail
			local mail_ext = vector(
				fmt("Service: %s\n", service_str),
				fmt("Intel source: %s\n", item$meta$source));
			n$email_body_sections = mail_ext;

			NOTICE(n);
			}
		}
	}
