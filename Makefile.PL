package Apache::AuthChecker;
use ExtUtils::MakeMaker;
use Apache::ExtUtils qw(command_table);
use Apache::src();

@directives = (
    {
        name => 'PerlAuthCheckerMaxUsers',
        errmsg => 'number of records to store in shared memory',
        args_how => 'TAKE1',
        req_override => 'RSRC_CONF'
    },
        {
        name => 'PerlSecondsToExpire',
        errmsg => 'seconds to remember IP address and AUTH attempts',
        args_how => 'TAKE1',
        req_override => 'RSRC_CONF'
    },
);

command_table(\@directives);

WriteMakefile(
    'NAME'		=> 'Apache::AuthChecker',
    'VERSION_FROM'	=> 'AuthChecker.pm',
    'PREREQ_PM'		=> { IPC::Shareable => 0.60 }, 
    'LIBS'		=> [''],
    'DEFINE'		=> '',
    'INC'		=> Apache::src->new->inc,
);

__END__
