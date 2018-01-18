###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_CGI_45145.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Perl CGI.pm Header Values Newline Handling Unspecified Security Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Perl CGI.pm is prone to an unspecified security vulnerability related
to handling of newlines embedded in header values.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100929");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-12-02 12:48:19 +0100 (Thu, 02 Dec 2010)");
 script_bugtraq_id(45145);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2761");

 script_name("Perl CGI.pm Header Values Newline Handling Unspecified Security Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45145");
 script_xref(name : "URL" , value : "http://search.cpan.org/~lds/CGI.pm-3.50/");
 script_xref(name : "URL" , value : "http://www.perl.com");
 script_xref(name : "URL" , value : "http://perl5.git.perl.org/perl.git/commit/84601d63a7e34958da47dad1e61e27cb3bd467d1");

 script_tag(name:"qod_type", value:"executable_version");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

cmd  = "perl -MCGI -e 'print";
cmd += '"$CGI::VERSION"';
cmd += "'";

version = ssh_cmd(socket:sock, cmd:cmd, timeout:60);

if(!version || "not found" >< version || "..at..INC" >< version || version !~ "^[0-9.]+$")exit(0);

if(version_is_less(version: version, test_version: "3.50")) {
    security_message(0);
}

ssh_close_connection();
exit(0);

