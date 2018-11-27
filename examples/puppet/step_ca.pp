# step_ca package configuration
class step_ca(
  $version = false,
) {
  if !$version {
    fail("class ${name}: version cannot be empty")
  }

  $pkg = "step_${version}_linux_amd64.tar.gz"
  $download_url = "https://github.com/smallstep/certificates/releases/download/v${version}/step-certificates_${version}_linux_amd64.tar.gz"
  $step_ca_exec = '/opt/smallstep/bin/step-ca'

  exec {
    'download/update smallstep':
      command => "/usr/bin/curl --fail -o /tmp/${pkg} ${download_url} && /bin/tar -xzvf /tmp/${pkg} -C /opt",
      unless  => "/usr/bin/which ${step_exec} && ${step_exec} version | grep ${version}",
      user    => 'step',
      require => File['/opt/smallstep'];
  }

  file {
    '/usr/local/lib/step/.step':
      ensure  => directory,
      mode    => '0755',
      owner   => 'step';
    '/usr/local/lib/step/.step/secrets':
      ensure  => directory,
      mode    => '0644',
      owner   => 'step';
    '/usr/local/lib/step/.step/secrets/root_ca.crt': # Get this from Hiera.
      ensure  => file,
      mode    => '0644',
      owner   => 'step';
    '/usr/local/lib/step/.step/secrets/intermediate_ca.crt': # Get this from Hiera.
      ensure  => file,
      mode    => '0644',
      owner   => 'step';
    '/usr/local/lib/step/.step/secrets/intermediate_ca_key': # Get this from Hiera.
      ensure  => file,
      mode    => '0644',
      owner   => 'step';
    '/usr/local/lib/step/.step/secrets/intermediate_pass': # Get this from Hiera.
      ensure  => file,
      mode    => '0644',
      owner   => 'step';
    '/usr/local/lib/step/.step/config':
      ensure  => directory,
      mode    => '0755',
      owner   => 'step';
    '/usr/local/lib/step/.step/config/ca.json': # Fill from template in repo.
      ensure  => file,
      content => template('ca.json.erb'),
      mode    => '0755',
      owner   => 'step';
    '/usr/local/lib/step/.step/config/ca.json': # Fill from template in repo.
      ensure  => file,
      content => template('defaults.json.erb'),
      mode    => '0755',
      owner   => 'step';
  }

  service { $name:
    ensure    => running,
    start => "${step_ca_exec} /usr/local/lib/step/.step/config/ca.json --password-file /usr/local/lib/step/.step/secrets/intermediate_pass",
    provider  => 'systemd',
  }
}
