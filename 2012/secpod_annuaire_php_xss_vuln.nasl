###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_annuaire_php_xss_vuln.nasl 9425 2018-04-10 12:38:38Z cfischer $
#
# Annuaire PHP 'sites_inscription.php' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902787");
  script_version("$Revision: 9425 $");
  script_cve_id("CVE-2012-0899");
  script_bugtraq_id(51434);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-10 14:38:38 +0200 (Tue, 10 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-24 18:49:12 +0530 (Tue, 24 Jan 2012)");
  script_name("Annuaire PHP 'sites_inscription.php' Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72407");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/108719/annuaire-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow the attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of a vulnerable site.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Annuaire PHP");
  script_tag(name : "insight" , value : "The flaw is due to an input passed via the 'url' and 'nom'
  parameters to 'sites_inscription.php' page is not properly verified before it
  is returned to the user.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Annuaire PHP and is prone to cross site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


anPort = "";
dir = "";
anReq = "";
anRes = "";

## Get HTTP Port
anPort = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:anPort)){
  exit(0);
}

## Iterate over the paths
foreach dir (make_list_unique("/", "/annuaire", "/Annuaire", cgi_dirs(port:anPort)))
{

  if(dir == "/") dir = "";

  anReq = http_get(item:string(dir,"/admin/index.php"), port:anPort);
  anRes = http_keepalive_send_recv(port:anPort, data:anReq);

  ## Confirm the application
  if(">Annuaire" >< anRes || "annuaire<" >< anRes)
  {

    ## Construct attack
    url = string (dir + "/referencement/sites_inscription.php?nom=xss&url=" +
                        "><script>alert(document.cookie)</script>");

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:anPort, url:url, pattern:"<script>alert\(document.cookie\)</script>",
       extra_check:make_list("<title>Annuaire", "compte_annu.php"), check_header:TRUE))
    {
      security_message(port:anPort);
      exit(0);
    }
  }
}

exit(99);
