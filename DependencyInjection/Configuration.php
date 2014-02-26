<?php

namespace EWZ\Bundle\RecaptchaBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('ewz_recaptcha');

        $rootNode
            ->children()
                ->scalarNode('public_key')->isRequired()->end()
                ->scalarNode('private_key')->isRequired()->end()
                ->booleanNode('secure')->defaultFalse()->end()
                ->booleanNode('enabled')->defaultTrue()->end()
                ->scalarNode('locale_key')->defaultValue('kernel.default_locale')->end()
            ->end()
        ;
        
        $this->addHttpClientConfiguration($rootNode);
        
        return $treeBuilder;
    }
    
    private function addHttpClientConfiguration(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('http_proxy')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('type')->defaultValue(null)->end()
                        ->scalarNode('host')->defaultValue(null)->end()
                        ->scalarNode('port')->defaultValue(null)->end()
                        ->scalarNode('auth')->defaultValue(null)->end()
                    ->end()
                ->end()
            ->end()
        ;
    }
    
}
