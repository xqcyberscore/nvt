###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_registry_violation.nasl 4928 2017-01-03 09:00:28Z cfi $
#
# Windows Registry Check: Violations
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.105990");
  script_version("$Revision: 4928 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-03 10:00:28 +0100 (Tue, 03 Jan 2017) $");
  script_tag(name:"creation_date", value:"2015-05-22 12:45:52 +0700 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Registry Check: Violations");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("policy_registry.nasl");
  script_mandatory_keys("policy/registry_violation");

  script_tag(name:"summary", value:"List registry entries which didn't pass the registry
  policy check.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

violations = get_kb_item("policy/registry_violation");

if (violations) {
  report = 'The following registry entries did not pass the registry policy check:\n\n';
  report += 'Registry entry | Present | Value checked against | Value set in registry\n' + violations;
  log_message(data:report, port:0);
}

exit(0);
