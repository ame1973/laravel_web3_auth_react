import React, {useEffect, useState} from 'react';
import Button from '@/Components/Button';
import Checkbox from '@/Components/Checkbox';
import Guest from '@/Layouts/Guest';
import Input from '@/Components/Input';
import Label from '@/Components/Label';
import ValidationErrors from '@/Components/ValidationErrors';
import {Head, Link, useForm} from '@inertiajs/inertia-react';

export default function Login({status, canResetPassword}) {
    const {data, setData, post, processing, errors, reset} = useForm({
        email: '',
        password: '',
        remember: '',
    });
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        return () => {
            reset('password');
        };
    }, []);

    const onHandleChange = (event) => {
        setData(event.target.name, event.target.type === 'checkbox' ? event.target.checked : event.target.value);
    };

    const submit = (e) => {
        e.preventDefault();

        post(route('login'));
    };

    const loginMetaMask = async () => {
        setLoading(true);

        if (!window.ethereum) {
            alert('Metamask not exist');
            setLoading(true);
            return;
        }

        const web3 = new Web3(window.ethereum);

        // Fetch nonce
        const message = (await axios.get(route('metamask.signature'))).data;
        // Get wallet address
        const address = (await web3.eth.requestAccounts())[0];
        // Sign message
        const signature = await web3.eth.personal.sign(message, address);

        try {
            let response = await axios.post(route('metamask.authenticate'), {
                'address': address,
                'signature': signature,
            });

            window.location.href = route('dashboard');
        } catch(e) {
            alert(e.message);
        }

        setLoading(false);
    }

    return (
        <Guest>
            <Head title="Log in"/>

            {status && <div className="mb-4 font-medium text-sm text-green-600">{status}</div>}

            <ValidationErrors errors={errors}/>

            <form onSubmit={submit}>
                <div>
                    <Label forInput="email" value="Email"/>

                    <Input
                        type="text"
                        name="email"
                        value={data.email}
                        className="mt-1 block w-full"
                        autoComplete="username"
                        isFocused={true}
                        handleChange={onHandleChange}
                    />
                </div>

                <div className="mt-4">
                    <Label forInput="password" value="Password"/>

                    <Input
                        type="password"
                        name="password"
                        value={data.password}
                        className="mt-1 block w-full"
                        autoComplete="current-password"
                        handleChange={onHandleChange}
                    />
                </div>

                <div className="block mt-4">
                    <label className="flex items-center">
                        <Checkbox name="remember" value={data.remember} handleChange={onHandleChange}/>

                        <span className="ml-2 text-sm text-gray-600">Remember me</span>
                    </label>
                </div>

                <div className="flex items-center justify-end mt-4">
                    {canResetPassword && (
                        <Link
                            href={route('password.request')}
                            className="underline text-sm text-gray-600 hover:text-gray-900"
                        >
                            Forgot your password?
                        </Link>
                    )}

                    <Button className="ml-4" processing={processing}>
                        Log in
                    </Button>
                </div>
            </form>

            <hr className={'mt-3'}/>
            <div className={'flex justify-center'}>
                <button
                    className={
                        `inline-flex items-center px-4 py-2 bg-gray-900 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest active:bg-gray-900 transition ease-in-out duration-150 ${
                            loading && 'opacity-25'
                        } mt-4`
                    }
                    onClick={loginMetaMask}
                    disabled={loading}
                >
                    Login with MetaMask
                </button>
            </div>
        </Guest>
    );
}
