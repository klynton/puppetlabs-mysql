# frozen_string_literal: true

require 'spec_helper'

shared_examples 'mysql::password function' do
  it 'exists' do
    expect(subject).not_to be_nil
  end

  it 'raises a ArgumentError if there is less than 1 arguments' do
    expect(subject).to run.with_params.and_raise_error(ArgumentError)
  end

  it 'raises a ArgumentError if there is more than 2 arguments' do
    expect(subject).to run.with_params('foo', false, 'bar').and_raise_error(ArgumentError)
  end

  it 'converts password into a hash' do
    expect(subject).to run.with_params('password').and_return('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19')
  end

  it 'accept password as Sensitive' do
    expect(subject).to run.with_params(sensitive('password')).and_return('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19')
  end

  # Test of a Returnvalue of Datatype Sensitive does not work
  it 'returns Sensitive with sensitive=true' do
    expect(subject).to run.with_params('password', true).and_return(sensitive('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'))
  end

  it 'password should be String' do
    expect(subject).to run.with_params(123).and_raise_error(ArgumentError)
  end

  it 'converts an empty password into a empty string' do
    expect(subject).to run.with_params('').and_return('')
  end

  it 'converts the password when its given in caps with * sign' do
    expect(subject).to run.with_params('AFDJKFD1*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29').and_return('*91FF6DD4E1FC57D2EFC57F49552D0596F7D46BAF')
  end

  it 'does not convert a password that is already a hash' do
    expect(subject).to run.with_params('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19').and_return('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19')
  end
end

context 'with caching_sha2_password plugin' do
  before(:each) do
    # Mock the @plugin instance variable
    allow_any_instance_of(subject).to receive(:instance_variable_get).with(:@plugin).and_return('caching_sha2_password')
  end

  it 'generates a SHA256 hash for a regular password' do
    result = subject.execute('password')
    expect(result).to match(/^\$A\$005\$[A-Za-z0-9.\/]{20}[A-Za-z0-9.\/]{43}$/)
  end

  it 'returns an empty string for an empty password' do
    is_expected.to run.with_params('').and_return('')
  end

  it 'generates different hashes for the same password due to salt' do
    result1 = subject.execute('password')
    result2 = subject.execute('password')
    expect(result1).not_to eq(result2)
  end

  it 'accepts password as Sensitive' do
    result = subject.execute(sensitive('password'))
    expect(result).to match(/^\$A\$005\$[A-Za-z0-9.\/]{20}[A-Za-z0-9.\/]{43}$/)
  end

  it 'returns Sensitive with sensitive=true' do
    result = subject.execute('password', true)
    expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
    expect(result.unwrap).to match(/^\$A\$005\$[A-Za-z0-9.\/]{20}[A-Za-z0-9.\/]{43}$/)
  end

  it 'does not convert a password that is already a hash' do
    hash = '$A$005$ABCDEFGHIJKLMNOPQRST123456789012345678901234567890123'
    expect(subject.execute(hash)).to eq(hash)
  end
end

describe 'mysql::password' do
  it_behaves_like 'mysql::password function'

  describe 'non-namespaced shim' do
    describe 'mysql_password', type: :puppet_function do
      it_behaves_like 'mysql::password function'
    end
  end
end
