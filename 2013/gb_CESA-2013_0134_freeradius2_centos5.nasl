###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for freeradius2 CESA-2013:0134 centos5 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "FreeRADIUS is an open-source Remote Authentication Dial-In User Service
  (RADIUS) server which allows RADIUS clients to perform authentication
  against the RADIUS server. The RADIUS server may optionally perform
  accounting of its operations using the RADIUS protocol.

  It was found that the &quot;unix&quot; module ignored the password expiration
  setting in &quot;/etc/shadow&quot;. If FreeRADIUS was configured to use this module
  for user authentication, this flaw could allow users with an expired
  password to successfully authenticate, even though their access should have
  been denied. (CVE-2011-4966)
  
  This update also fixes the following bugs:
  
  * After log rotation, the freeradius logrotate script failed to reload the
  radiusd daemon and log messages were lost. This update has added a command
  to the freeradius logrotate script to reload the radiusd daemon and the
  radiusd daemon re-initializes and reopens its log files after log rotation
  as expected. (BZ#787111)
  
  * The radtest script with the &quot;eap-md5&quot; option failed because it passed the
  IP family argument when invoking the radeapclient utility and the
  radeapclient utility did not recognize the IP family. The radeapclient
  utility now recognizes the IP family argument and radtest now works with
  eap-md5 as expected. (BZ#846476)
  
  * Previously, freeradius was compiled without the &quot;--with-udpfromto&quot;
  option. Consequently, with a multihomed server and explicitly specifying
  the IP address, freeradius sent the reply with the wrong IP source address.
  With this update, freeradius has been built with the &quot;--with-udpfromto&quot;
  configuration option and the RADIUS reply is always sourced from the IP
  address the request was sent to. (BZ#846471)
  
  * Due to invalid syntax in the PostgreSQL admin schema file, the FreeRADIUS
  PostgreSQL tables failed to be created. With this update, the syntax has
  been adjusted and the tables are created as expected. (BZ#818885)
  
  * FreeRADIUS has a thread pool that dynamically grows based on load. If
  multiple threads using the &quot;rlm_perl()&quot; function are spawned in quick
  succession, the FreeRADIUS server sometimes terminated unexpectedly with a
  segmentation fault due to parallel calls to the &quot;rlm_perl_clone()&quot;
  function. With this update, a mutex for the threads has been added and the
  problem no longer occurs. (BZ#846475)
  
  * The man page for &quot;rlm_dbm_parser&quot; was incorrectly installed as
  &quot;rlm_dbm_parse&quot;, omitting the trailing &quot;r&quot;. The man page now correctly
  appears as rlm_dbm ... 

  Description truncated, for more information please check the Reference URL";


tag_affected = "freeradius2 on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019141.html");
  script_id(881566);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:00 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2011-4966");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2013:0134");
  script_name("CentOS Update for freeradius2 CESA-2013:0134 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of freeradius2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"freeradius2", rpm:"freeradius2~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-krb5", rpm:"freeradius2-krb5~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-ldap", rpm:"freeradius2-ldap~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-mysql", rpm:"freeradius2-mysql~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-perl", rpm:"freeradius2-perl~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-postgresql", rpm:"freeradius2-postgresql~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-python", rpm:"freeradius2-python~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-unixODBC", rpm:"freeradius2-unixODBC~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-utils", rpm:"freeradius2-utils~2.1.12~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
