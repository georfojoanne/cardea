import React, { useState } from 'react';
import { Eye, EyeOff, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

// You would replace these with actual SVGs or icon components for Google/Apple
const GoogleIcon = () => (
    <svg className="h-5 w-5" viewBox="0 0 24 24">
        <path
            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            fill="#4285F4"
        />
        <path
            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            fill="#34A853"
        />
        <path
            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
            fill="#FBBC05"
        />
        <path
            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
            fill="#EA4335"
        />
    </svg>
);

const MicrosoftIcon = () => (
  <svg className="h-5 w-5" viewBox="0 0 23 23">
    <path fill="#f35325" d="M1 1h10v10H1z"/>
    <path fill="#81bc06" d="M12 1h10v10H12z"/>
    <path fill="#05a6f0" d="M1 12h10v10H1z"/>
    <path fill="#ffba08" d="M12 12h10v10H12z"/>
  </svg>
);

interface LoginPageProps {
    onSubmit?: (data: any) => Promise<void>;
}

const LoginPage: React.FC<LoginPageProps> = ({ onSubmit }) => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({ email: '', password: '' });
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (error) setError(null);
    };

    // Secret dev admin credentials - REMOVE IN PRODUCTION
    const DEV_ADMIN = {
        email: 'admin@cardea.dev',
        password: 'cardea2026!'
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);

        try {
            // Dev bypass: Check for secret admin account
            if (formData.email === DEV_ADMIN.email && formData.password === DEV_ADMIN.password) {
                await new Promise((resolve) => setTimeout(resolve, 500)); // Brief delay for UX
                localStorage.setItem('cardea_dev_auth', 'true');
                navigate('/dashboard');
                return;
            }

            if (onSubmit) {
                await onSubmit(formData);
            } else {
                // No backend configured - show error for non-dev accounts
                throw new Error('Auth backend not configured');
            }
            navigate('/dashboard');
        } catch (err) {
            setError('Invalid email or password. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        // Main Container - Splits into two columns on large screens
        <div className="min-h-screen w-full flex bg-white">

            {/* Left Section - Login Form */}
            <div className="w-full lg:w-1/2 flex flex-col justify-between p-8 lg:p-24">
                <div>
                    {/* Logo Placeholder */}
                    <div className="flex items-center mb-16">
                        <div className="h-8 w-8 bg-blue-600 rounded-full flex items-center justify-center mr-2">
                            <div className="h-4 w-4 border-2 border-white rounded-full"></div>
                        </div>
                        <h1 className="text-xl font-bold text-gray-900">Cardea</h1>
                    </div>

                    {/* Header */}
                    <div className="mb-10">
                        <h2 className="text-4xl font-bold text-gray-900 mb-3">
                            Welcome Back
                        </h2>
                        <p className="text-gray-600 text-lg">
                            Enter your email and password to access your account.
                        </p>
                    </div>

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <label htmlFor="email" className="block text-sm font-semibold text-gray-700">
                                Email
                            </label>
                            <input
                                id="email"
                                name="email"
                                type="email"
                                required
                                placeholder="user@company.com"
                                value={formData.email}
                                onChange={handleChange}
                                className="block w-full px-4 py-3 rounded-xl border border-gray-200 
                         text-gray-900 placeholder-gray-400
                         focus:ring-2 focus:ring-blue-600 focus:border-transparent
                         transition-all duration-200 bg-gray-50"
                            />
                        </div>

                        <div className="space-y-2">
                            <label htmlFor="password" className="block text-sm font-semibold text-gray-700">
                                Password
                            </label>
                            <div className="relative">
                                <input
                                    id="password"
                                    name="password"
                                    type={showPassword ? 'text' : 'password'}
                                    required
                                    placeholder="••••••••"
                                    value={formData.password}
                                    onChange={handleChange}
                                    className="block w-full px-4 py-3 rounded-xl border border-gray-200 
                           text-gray-900 placeholder-gray-400
                           focus:ring-2 focus:ring-blue-600 focus:border-transparent
                           transition-all duration-200 bg-gray-50 pr-12"
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-400 hover:text-gray-600"
                                >
                                    {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                                </button>
                            </div>
                        </div>

                        {error && (
                            <div className="p-3 rounded-lg bg-red-50 text-red-600 text-sm font-medium">
                                {error}
                            </div>
                        )}

                        <div className="flex items-center justify-between">
                            <div className="flex items-center">
                                <input
                                    id="remember-me"
                                    type="checkbox"
                                    className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-600"
                                />
                                <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-600">
                                    Remember Me
                                </label>
                            </div>
                            <button type="button" className="text-sm font-semibold text-blue-600 hover:text-blue-700">
                                Forgot Your Password?
                            </button>
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading}
                            className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white 
                       rounded-xl font-semibold text-lg shadow-sm
                       focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-600 
                       disabled:opacity-70 transition-all duration-200"
                        >
                            {isLoading ? (
                                <span className="flex items-center justify-center">
                                    <Loader2 className="animate-spin h-5 w-5 mr-2" />
                                    Logging In
                                </span>
                            ) : (
                                'Log In'
                            )}
                        </button>

                        {/* Social Login Section */}
                        <div className="mt-8">
                            <div className="relative">
                                <div className="absolute inset-0 flex items-center">
                                    <div className="w-full border-t border-gray-200"></div>
                                </div>
                                <div className="relative flex justify-center text-sm">
                                    <span className="px-4 bg-white text-gray-500 font-medium">
                                        Or Login With
                                    </span>
                                </div>
                            </div>

                            <div className="mt-6 grid grid-cols-2 gap-4">
                                <button
                                    type="button"
                                    className="flex items-center justify-center px-4 py-3 border border-gray-200 
                           rounded-xl shadow-sm bg-white text-sm font-medium text-gray-700 
                           hover:bg-gray-50 transition-all"
                                >
                                    <GoogleIcon />
                                    <span className="ml-3">Google</span>
                                </button>
                                <button
                                    type="button"
                                    className="flex items-center justify-center px-4 py-3 border border-gray-200 
                           rounded-xl shadow-sm bg-white text-sm font-medium text-gray-700 
                           hover:bg-gray-50 transition-all"
                                >
                                    <MicrosoftIcon />
                                    <span className="ml-3">Microsoft</span>
                                </button>
                            </div>
                        </div>

                        <p className="mt-8 text-center text-sm text-gray-600 font-medium">
                            Don't Have An Account?{' '}
                            <button className="text-blue-600 hover:text-blue-700 font-semibold">
                                Register Now.
                            </button>
                        </p>
                    </form>
                </div>

                {/* Footer */}
                <div className="mt-12 flex items-center justify-between text-sm text-gray-500 font-medium">
                    <p>Copyright © 2025 Cardea</p>
                    <button className="hover:text-gray-700">Privacy Policy</button>
                </div>
            </div>

            {/* Right Section - Promo/Image */}
            <div className="hidden lg:flex w-1/2 bg-blue-600 p-24 flex-col justify-center relative overflow-hidden">
                {/* Background Design Element */}
                <div className="absolute top-0 right-0 -mt-20 -mr-20 text-blue-500 opacity-20">
                    <svg width="400" height="400" viewBox="0 0 400 400" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="200" cy="200" r="200" fill="currentColor" />
                    </svg>
                </div>

                <div className="relative z-10">
                    <h2 className="text-4xl font-bold text-white mb-6 leading-tight">
                        Stay one step ahead of every threat.
                    </h2>
                    <p className="text-blue-100 text-lg mb-12">
                        Instant detection. Immediate protection.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;