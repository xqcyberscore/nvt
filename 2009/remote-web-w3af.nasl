##############################################################################
# OpenVAS Vulnerability Test
#
# Assess web security with w3af
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This plugin uses w3af (w3af_console to be exact) to find  
web security issues.

See the preferences section for w3af options.

Note that OpenVAS is using limited set of w3af options.
Therefore, for more complete web assessment, you should
use standalone w3af tool for deeper/customized checks.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80109");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-10-18 22:12:25 +0200 (Sun, 18 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("w3af (NASL wrapper)");
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
 script_family("Web application abuses");
 script_add_preference(name: "Profile", type:"radio",value:"fast_scan;sitemap;web_infrastructure;OWASP_TOP10;audit_high_risk;bruteforce;full_audit");
 script_add_preference(name: "Seed URL", type: "entry", value: "");
 script_add_preference(name: 'Report broken w3af installation', value: 'no', type: 'checkbox');
 script_dependencies("find_service.nasl","httpver.nasl","http_login.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("global_settings.inc"); # For report_verbosity

cmdw3af = "w3af_console";

port = get_http_port( default:80 );

encaps = get_port_transport(port);
if (encaps > ENCAPS_IP) httprefix="https://";
else httprefix="http://";

httpver = get_kb_item("http/"+port);
if (httpver == "11") {
	httparg=get_host_name();
} else {
	httparg=get_host_ip();
}

httpurl=httprefix+httparg+":"+port;

seed = script_get_preference ("Seed URL");
if (seed)
{
  if (ereg(pattern: "^/", string: seed))
  {
    httpurl = httpurl + seed;
  }
  else
  {
    httpurl = httpurl + "/" + seed;
  }
}

useprofile=script_get_preference("Profile");
if (!useprofile) useprofile = "fast_scan";

genfilename = get_tmp_dir() + "openvas-w3af-" + get_host_ip() + "-" + port;
cmdfilename = genfilename + ".cmd";
repfilename = genfilename + ".rep";
httpfilename = genfilename + ".http";

cmddata ="profiles use "+useprofile+'\n';
cmddata = cmddata + 'plugins\n';
# console doesn't work, so we use textFile
# termios error: (25, 'Inappropriate ioctl for device')
# cmddata = cmddata + 'output console\n';
# cmddata = cmddata + 'output config console\n';  
cmddata = cmddata + 'output textFile\n';
cmddata = cmddata + 'output config textFile\n';
if (report_verbosity > 1) {
	cmddata = cmddata + 'set verbose True\n';
} else {
	cmddata = cmddata + 'set verbose False\n';
}
cmddata = cmddata + 'set httpFileName '+httpfilename+'\n';
cmddata = cmddata + 'set fileName '+repfilename+'\n';
cmddata = cmddata + 'back\n';
cmddata = cmddata + 'back\n';

cookie=get_kb_item("/tmp/http/auth/"+port);
if(cookie) {
  headersfile = genfilename + ".header";
  fwrite(data:string(cookie), file:headersfile);
  cmddata = cmddata + 'http-settings\n';
  cmddata = cmddata + 'set  headersFile ' + headersfile + '\n';
  cmddata = cmddata + 'back\n';

} else {

  auth = get_kb_item("http/auth");
  if(auth) {
   headersfile = genfilename + ".header";
   fwrite(data:auth, file:headersfile);
   cmddata = cmddata + 'http-settings\n';
   cmddata = cmddata + 'set  headersFile ' + headersfile + '\n';
   cmddata = cmddata + 'back\n';
 }
}

cmddata = cmddata + 'target\n';
cmddata = cmddata + 'set target ' + httpurl+ '\n';
cmddata = cmddata + 'back\n';

cmddata = cmddata + 'start\n';
cmddata = cmddata + 'exit\n';

function on_exit()
{
	if (file_stat(cmdfilename)) unlink(cmdfilename);
	if (file_stat(httpfilename)) unlink(httpfilename);
	if (file_stat (repfilename)) unlink(repfilename);
	if(headersfile && file_stat (headersfile))unlink(headersfile);
}

fwrite(data:cmddata, file:cmdfilename);

report_broken = script_get_preference("Report broken w3af installation");

if ( ! find_in_path(cmdw3af) )
{
    if( report_broken != 'yes' ) exit( 0 );
    text = 'w3af could not be found in your system path.\n';
    text += 'OpenVAS was unable to execute w3af and to perform the scan you
requested.\nPlease make sure that w3af is installed and that '+cmdw3af+' is
available in the PATH variable defined for your environment.';
    log_message(port: port, data: text);
    exit(0);
}

i = 0;
argv[i++] = cmdw3af;
argv[i++] = "-s"; argv[i++] = cmdfilename;

r = pread(cmd: cmdw3af, argv: argv, cd: 1);
if (! r) exit(0);	# error

if (file_stat(repfilename)) {
	rfile=fread(repfilename);
	report = 'Here is the w3af report:\n';
	report += rfile;

        report = ereg_replace(string:report,pattern:"(Finished scanning process.)(.*)",replace:"\1" + '\n\n');

	# rhttp=fread(httpfilename);
	if ('- vulnerability ]' >< report) {
		security_message(port: port, data: report);
	} else {
		log_message(port: port, data: report);
	}
} else {
        if( report_broken != 'yes' ) exit( 0 );
	text  = 'w3af report filename is empty. that could mean that\n';
	text += 'wrong version of w3af is used or tmp dir is not accessible.\n';
	text += 'In short: check installation of w3af and OpenVAS';
	log_message(port: port, data: text);
}
