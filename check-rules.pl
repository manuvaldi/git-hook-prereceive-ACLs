#!/usr/bin/perl

use warnings;
use strict;
use Data::Dumper;


# Configuration ###############################
my $debuglevel=10;
###############################################

# Variables
my $stdin;
my ($oldref,$newref,$refname);
my $branchname;
#my @references;
my $shortref;
my $ACL;
my @obs;
my $defaultaction="ALLOW";
my $resultadosreglas;
my $bloquear="NO";

### Inicio Script ###
# Commiter, repo, log file variables

my $commiter = $ENV{'STASH_USER_NAME'}; 
my $reponame = $ENV{'STASH_REPO_NAME'};
my $aclfile  = $ARGV[0] || die("El fichero de reglas no existe");
my $dryrun = $ARGV[1] || "";
my $log_file = "/tmp/hook_prereceive_$reponame.log";

# Open logfile
open(LOG, ">>", $log_file);


# Captura entrada y parametros
	logtext(0,"---------- ".`echo -n \$(date)`." ----------");
	logtext(3,"Capturando entrada y parametros");
	$stdin= <STDIN>;
	chomp($stdin);
	$oldref  = (split(/ /,$stdin))[0];
	$newref  = (split(/ /,$stdin))[1];
	$refname = (split(/ /,$stdin))[2];
	chomp($oldref);
	chomp($newref);
	chomp($refname);
	logtext(3,"STDIN    : $stdin");
	logtext(3,"ACL FILE : $aclfile");
	if ($dryrun eq "dryrun") {
		$dryrun="true";
		logtext(0,"Running in DRY MODE");
	} else {
		$dryrun="false";
	}


# Chequear si es un commit a rama/head ref
	if ( $refname =~ m/^refs\/heads\/(.*)/ ) {
		$branchname=$1;
	} else {
		logtext(0,"No es un commit a rama/head ($refname)");
		exit 0;
	}

# Load ACLs
	$ACL = loadacls($aclfile);
	logtext(5, Dumper($ACL));

	@obs = loadfiles($oldref,$newref);
	logtext(5,Dumper(\@obs));

# Comprobando reglas
	logtext(0,"");
	logtext(0,"Comprobando reglas...");
	foreach my $file (@obs) {
		logtext(0," * Comprobado: $branchname // $commiter // $file");
		my $actionresult=$defaultaction;
		foreach my $regla (sort(keys %$ACL)) {
			logtext(5,"   - Regla $regla");
			logtext(5,"      ".Dumper($ACL->{$regla}));
			if ( $branchname =~ m/^$ACL->{$regla}->{RAMA}$/i ) {
				logtext(1,"    !! OK - regla $regla en campo RAMA");
			} else {
				logtext(2,"    !! STOP - regla $regla en campo RAMA");
				next;
			}
			if ( $ACL->{$regla}->{USUARIO} =~ m/^($commiter,.*|.*,$commiter,.*|.*,$commiter|$commiter)$/i || $commiter =~ m/$ACL->{$regla}->{USUARIO}/ ) {
				logtext(1,"    !! OK - regla $regla en campo USUARIO");
			} else {
				logtext(1,"    !! STOP - regla $regla en campo USUARIO");

				next;
			}
			if ( $file =~ m/^$ACL->{$regla}->{FICHERO}$/i ) {
				logtext(1,"    !! OK - regla $regla en campo FICHERO");
			} else {
				logtext(1,"    !! STOP - regla $regla en campo FICHERO");
				next;
			}

			if ( $ACL->{$regla}->{ACCION} =~ m/^(ALLOW|DENY|WARNING)$/i ) {
				logtext(1,"    !! OK - regla $regla en campo ACCION");
				logtext(4,"    ** Actualizando accion: $actionresult ---> ".$ACL->{$regla}->{ACCION});
				$actionresult=$ACL->{$regla}->{ACCION};
			} else {
				logtext(1,"    !! STOP - regla $regla en campo ACCION");
			}
		}
		logtext(0," ** RESULTADO para FILE: $file = $actionresult\n\n");
		$resultadosreglas->{$file}=$actionresult;

		if ( $resultadosreglas->{$file} eq "DENY" ) { # Para detectar si algun fichero esta DENY
			$bloquear="SI";
		}
	}

# Imprimiendo resultados
	logtext(-1," Imprimiendo resultados de las reglas ");
	logtext(-1,"--------------------------------------");
	logtext(-1," RAMA     : $branchname");
	logtext(-1," Commiter : $commiter");
	foreach my $file (keys %$resultadosreglas) {
		logtext(0,sprintf(" %10s ---> %s",$resultadosreglas->{$file},$file));
		printf("  %-10s ---> %s\n",$resultadosreglas->{$file},$file);
	}
	
if ( $bloquear eq "SI" ) {
	logtext(-1," !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logtext(-1," !!!! Algun fichero commiteado no esta permitido. Reviselo con su administrador  ");
	logtext(-1," !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	logtext(1,"--------------- Fin script --------------");
	logtext(0,"");
	if ($dryrun eq "true") {
		exit 0;
	} else {
		exit 1;
	}
} else {
	logtext(1,"--------------- Fin script --------------");
	logtext(0,"");
	exit 0;

}




exit 0;









####### DECLARACION DE FUNCIONES ###################################3
sub logtext {

	my $level=$_[0];
	my $text=$_[1];

	if ($level <= $debuglevel) {
		print LOG " $text\n";
	}
	if ($level == -1) {
		print " $text\n";
	}
}


sub loadacls {
	my $filename=$_[0];
	my $acls;
	my $fh;
	

	if ( ! open($fh, '<:encoding(UTF-8)', $filename) ) { 
		logtext(-1,"[ERROR] - No se pudo abrir el fichero de ACLs para el proyecto '$filename'");
		exit 1; 
	};
	
	logtext(1,"Leyendo ACLs y cargando en memoria");
	# Recorriendo fichero de ACLS y cargando en variable
	my $indice=0;
 	while (my $row = <$fh>) {
		chomp($row);
		if ( $row !~ /^\s*#.*/ && $row =~ m/^[\s|\t]*(\S*)[\s|\t]+(\S*)[\s|\t]+(\S*)[\s|\t]+(\S*)[\s|\t]*.*$/ ) {
			$indice++;
			logtext(1, "Leyendo ACL line: $row");
			my ($rama,$usuario,$fichero,$accion)=($1,$2,$3,$4);
			logtext(1, "  Rama    : $rama");
			logtext(1, "  Usuario : $usuario");
			logtext(1, "  Fichero : $fichero");
			logtext(1, "  Accion  : $accion");
		
			$acls->{$indice}->{RAMA}    =$rama;
			$acls->{$indice}->{USUARIO} =$usuario;
			$acls->{$indice}->{FICHERO} =$fichero;
			$acls->{$indice}->{ACCION}  =$accion;
			
		}
	}
	return $acls;
}


sub loadfiles {
	my $oldref=$_[0];
	my $newref=$_[1];

	my @obs;

	logtext(1,"Leyendo files modificados y cargando en memoria");
	foreach my $ref (`git rev-list $oldref..$newref`) {
		chomp($ref);
		logtext(5,"Referencia: $ref");
		my $shortref=substr($ref, 0, 7);
		foreach my $file (`git log -1 --name-only --pretty=format:'' $ref | grep -v '^\$' `) {
			chomp($file);
			logtext(5,"$shortref - $file");
			push(@obs,$file);
			
		}
		
	}
	return @obs;
}
